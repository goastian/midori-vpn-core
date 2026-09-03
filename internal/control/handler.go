package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/billing"
	"github.com/goastian/midori-vpn-core/internal/clientpki"
	"github.com/goastian/midori-vpn-core/internal/config"
	vpnCrypto "github.com/goastian/midori-vpn-core/internal/crypto"
	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/desiredstate"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/nodeauth"
	"github.com/goastian/midori-vpn-core/internal/proxytoken"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/respond"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

// deviceNameRe allows only safe characters for Content-Disposition filenames.
var deviceNameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// endpointHostRe allows hostnames, IPv4, and bracketed IPv6 addresses.
// It does not allow slashes, query strings, or protocol schemes.
var endpointHostRe = regexp.MustCompile(`^[a-zA-Z0-9._\[\]:-]+$`)

// validateServerEndpoint checks that an optional WireGuard endpoint is a safe
// host:port pair or plain host.
func validateServerEndpoint(endpoint string) error {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return nil
	}
	if strings.Contains(trimmed, "/") || strings.Contains(trimmed, "?") || strings.Contains(trimmed, "@") {
		return errors.New("endpoint must not contain path, query, or credentials")
	}
	host := trimmed
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		host = h
	}
	if !endpointHostRe.MatchString(host) {
		return errors.New("endpoint host contains invalid characters")
	}
	return nil
}

// sanitizeDeviceName strips unsafe characters, truncates to 64 chars, and
// defaults to "device" if the result is empty.
func sanitizeDeviceName(name string) string {
	name = deviceNameRe.ReplaceAllString(name, "")
	if len(name) > 64 {
		name = name[:64]
	}
	if name == "" {
		name = "device"
	}
	return name
}

// isValidWGKey checks if the provided key is a valid 32-byte base64-encoded
// WireGuard key (Curve25519 public key = 44 base64 chars).
func isValidWGKey(key string) bool {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return false
	}
	return len(raw) == 32
}

// BannedCheck is a middleware that rejects requests from banned users
// across all control routes (not just Connect).
func BannedCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r)
		if user != nil && user.IsBanned {
			respond.JsonError(w, "account is banned", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type Handler struct {
	userRepo                *repo.UserRepo
	serverRepo              *repo.ServerRepo
	peerRepo                *repo.PeerRepo
	peerOperationRepo       *repo.PeerOperationRepo
	deviceRepo              *repo.DeviceRepo
	meshRepo                *repo.MeshRepo
	auditRepo               *repo.AuditRepo
	trustedExtensionRepo    *repo.TrustedExtensionRepo
	billingClient           *billing.Client
	wgMgr                   *wg.Manager
	hub                     *WSHub
	maxDevicesPerUser       int
	appEnv                  string
	coreAllowLoopback       bool
	publicBaseURL           string
	vpnDNS                  string
	credentialSigningSecret string
	connectLimiter          *userRateLimiter // per-user rate limit for the /connect endpoint
	nodeVerifier            *nodeauth.Verifier
	clientCertificateRepo   *repo.DeviceCertificateRepo
	clientCertificateCA     *clientpki.Authority
	multiclusterRepo        *repo.MulticlusterRepo
	desiredStateSigner      *desiredstate.Signer
}

func (h *Handler) SetNodeVerifier(verifier *nodeauth.Verifier) {
	h.nodeVerifier = verifier
}

func (h *Handler) SetClientCertificateAuthority(authority *clientpki.Authority) {
	h.clientCertificateCA = authority
}

func NewHandler(pool *pgxpool.Pool, cfg *config.Config) *Handler {
	return NewHandlerWithMesh(pool, cfg, nil, nil)
}

func NewHandlerWithMesh(pool *pgxpool.Pool, cfg *config.Config, wgMgr *wg.Manager, hub *WSHub) *Handler {
	var dataCipher *dataencryption.Cipher
	if len(cfg.ControlDataEncryptionKey) > 0 {
		dataCipher, _ = dataencryption.New(cfg.ControlDataEncryptionKey)
	}
	return NewHandlerWithMeshAndDataEncryption(pool, cfg, wgMgr, hub, dataCipher)
}

func NewHandlerWithMeshAndDataEncryption(pool *pgxpool.Pool, cfg *config.Config, wgMgr *wg.Manager, hub *WSHub, dataCipher *dataencryption.Cipher) *Handler {
	billingRedis := billingRedisClient(cfg)
	h := &Handler{
		userRepo:                repo.NewUserRepo(pool),
		serverRepo:              repo.NewServerRepo(pool),
		peerRepo:                repo.NewPeerRepo(pool, dataCipher),
		peerOperationRepo:       repo.NewPeerOperationRepo(pool, dataCipher),
		deviceRepo:              repo.NewDeviceRepo(pool),
		meshRepo:                repo.NewMeshRepo(pool),
		auditRepo:               repo.NewAuditRepo(pool),
		trustedExtensionRepo:    repo.NewTrustedExtensionRepo(pool),
		clientCertificateRepo:   repo.NewDeviceCertificateRepo(pool),
		multiclusterRepo:        repo.NewMulticlusterRepo(pool),
		billingClient:           billing.NewClient(cfg, billingRedis),
		wgMgr:                   wgMgr,
		hub:                     hub,
		maxDevicesPerUser:       cfg.MaxDevicesPerUser,
		appEnv:                  cfg.AppEnv,
		coreAllowLoopback:       cfg.CoreAllowHTTP,
		publicBaseURL:           cfg.PublicBaseURL,
		vpnDNS:                  cfg.VpnDNS,
		credentialSigningSecret: cfg.CredentialSigningSecret,
	}
	if cfg.ControlNodeID != "" && cfg.ControlNodePrivateKey != "" {
		h.desiredStateSigner, _ = desiredstate.NewSigner(cfg.ControlNodeID, cfg.ControlNodePrivateKey)
	}
	if cfg.ConnectRateLimitRPS > 0 {
		h.connectLimiter = newUserRateLimiter(cfg.ConnectRateLimitRPS, cfg.ConnectRateLimitBurst)
	}
	return h
}

func billingRedisClient(cfg *config.Config) *redis.Client {
	if cfg == nil || cfg.RedisURL == "" {
		return nil
	}
	options, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		slog.Warn("billing: invalid Redis URL; entitlement caching disabled", "error", err)
		return nil
	}
	return redis.NewClient(options)
}

func (h *Handler) broadcastMeshListChanged() {
	if h.hub == nil {
		return
	}
	h.hub.Broadcast(meshEvent{Type: "mesh.list_changed"})
}

func (h *Handler) attachPeerToMeshSessions(ctx context.Context, userID uuid.UUID, peer *models.Peer) {
	if h.meshRepo == nil || peer == nil || !peer.IsActive {
		return
	}
	meshes, err := h.meshRepo.ListByUser(ctx, userID)
	if err != nil {
		return
	}
	changed := false
	for _, mesh := range meshes {
		if !isValidPublicMesh(&mesh) {
			continue
		}
		member, err := h.meshRepo.GetMember(ctx, mesh.ID, userID)
		if err != nil {
			continue
		}
		peerID := peer.ID
		if err := h.meshRepo.UpdateMemberPeer(ctx, mesh.ID, userID, &peerID); err == nil {
			changed = true
		}
		if h.wgMgr != nil {
			if wgErr := h.wgMgr.AddMeshIP(peer.PublicKey, member.MeshIP); wgErr != nil {
				slog.Warn("mesh: could not add mesh IP to WireGuard after connect",
					"peer_id", peer.ID, "mesh_id", mesh.ID, "error", wgErr)
			}
		}
	}
	if changed {
		h.broadcastMeshListChanged()
	}
}

func (h *Handler) detachPeerFromMeshSessions(ctx context.Context, peer *models.Peer) {
	if h.meshRepo == nil || peer == nil {
		return
	}
	if h.wgMgr != nil {
		if wgErr := h.wgMgr.RemoveMeshIP(peer.PublicKey); wgErr != nil {
			slog.Warn("mesh: could not remove mesh IP from WireGuard after disconnect",
				"peer_id", peer.ID, "error", wgErr)
		}
	}
	if err := h.meshRepo.ClearMemberPeerByPeerID(ctx, peer.ID); err == nil {
		h.broadcastMeshListChanged()
	}
}

func (h *Handler) getUserQuota(ctx context.Context, user *models.User) (models.UserQuota, error) {
	var breakdown models.DeviceTypeBreakdown
	usage, err := h.deviceRepo.ActiveUsageByUser(ctx, user.ID)
	if err != nil {
		return models.UserQuota{}, err
	}
	activeCount := 0
	for deviceType, count := range usage {
		activeCount += count
		switch deviceType {
		case models.DeviceTypeDesktop:
			breakdown.Desktop += count
		case models.DeviceTypeExtension:
			breakdown.Extension += count
		case models.DeviceTypeManual, models.DeviceTypeMobile:
			// Preserve the existing quota response shape until the Control UI
			// adopts the explicit device model in DEV-03.
			breakdown.Wireguard += count
		default:
			return models.UserQuota{}, fmt.Errorf("unsupported persisted device type %q", deviceType)
		}
	}

	maxDevices := h.maxDevicesPerUser
	planSlug := "free"
	planName := "Free Plan"

	if h.billingClient != nil {
		if sub, err := h.billingClient.GetUserSubscription(ctx, user.ID, user.AuthentikUID); err == nil && sub != nil {
			if sub.MaxDevices > 0 {
				maxDevices = sub.MaxDevices
			}
			if sub.PlanSlug != "" {
				planSlug = sub.PlanSlug
			}
			if sub.PlanName != "" {
				planName = sub.PlanName
			}
		}
	}

	if maxDevices <= 0 {
		maxDevices = 5
	}

	avail := maxDevices - activeCount
	if avail < 0 {
		avail = 0
	}

	return models.UserQuota{
		ConnectedDevices: activeCount,
		MaxDevices:       maxDevices,
		AvailableDevices: avail,
		PlanSlug:         planSlug,
		PlanName:         planName,
		DevicesByType:    breakdown,
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// User profile & Quota
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	quota, err := h.getUserQuota(r.Context(), user)
	if err != nil {
		respond.SafeError(w, "failed to load device quota", err, http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"id":            user.ID,
		"authentik_uid": user.AuthentikUID,
		"email":         user.Email,
		"display_name":  user.DisplayName,
		"groups":        user.Groups,
		"is_banned":     user.IsBanned,
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
		"quota":         quota,
	}
	respond.JsonOK(w, resp, http.StatusOK)
}

func (h *Handler) GetQuota(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	quota, err := h.getUserQuota(r.Context(), user)
	if err != nil {
		respond.SafeError(w, "failed to load device quota", err, http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, quota, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Servers (user-facing: list active only)
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) ListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListActive(r.Context())
	if err != nil {
		slog.Error("list servers error", "error", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}
	for index := range servers {
		usable := make([]models.TransportCapability, 0, len(servers[index].Transports))
		for _, transport := range servers[index].Transports {
			if transport.IsUsable() {
				usable = append(usable, transport)
			}
		}
		servers[index].SetTransports(usable)
		servers[index].ApplyCapabilities()
	}
	respond.JsonOK(w, servers, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Server latency ping
// ═══════════════════════════════════════════════════════════════════════════

type ServerPingResult struct {
	ServerID    uuid.UUID `json:"server_id"`
	Name        string    `json:"name"`
	Host        string    `json:"host"`
	Location    string    `json:"location"`
	CountryCode string    `json:"country_code"`
	LatencyMs   int64     `json:"latency_ms"`
	Available   bool      `json:"available"`
}

func (h *Handler) PingServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListActive(r.Context())
	if err != nil {
		slog.Error("ping servers list error", "error", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}

	respond.JsonOK(w, buildServerPingResults(servers), http.StatusOK)
}

func (h *Handler) AdminPingServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListAll(r.Context())
	if err != nil {
		slog.Error("admin ping servers list error", "error", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}

	respond.JsonOK(w, buildServerPingResults(servers), http.StatusOK)
}

func buildServerPingResults(servers []models.VPNServer) []ServerPingResult {
	results := make([]ServerPingResult, len(servers))
	var wg sync.WaitGroup

	for i, s := range servers {
		wg.Add(1)
		go func(idx int, server models.VPNServer) {
			defer wg.Done()
			result := ServerPingResult{
				ServerID:    server.ID,
				Name:        server.Name,
				Host:        server.Host,
				Location:    server.Location,
				CountryCode: server.CountryCode,
			}

			healthURL, _, err := coreURL(&server, "/health")
			if err != nil {
				results[idx] = result
				return
			}
			start := time.Now()

			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
			if err != nil {
				results[idx] = result
				return
			}

			resp, err := coreHTTP.Do(req)
			elapsed := time.Since(start).Milliseconds()

			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					result.LatencyMs = elapsed
					result.Available = true
				}
			}

			results[idx] = result
		}(i, s)
	}
	wg.Wait()

	return results
}

// ═══════════════════════════════════════════════════════════════════════════
// Connections — full VPN connection flow
// ═══════════════════════════════════════════════════════════════════════════

type ConnectRequest struct {
	ServerID       string         `json:"server_id"`
	PublicKey      string         `json:"public_key"`
	DeviceName     string         `json:"device_name"`
	Device         *DeviceRequest `json:"device,omitempty"`
	PQKEMPublicKey string         `json:"pq_kem_public_key,omitempty"`
}

func (h *Handler) respondWithExistingConnection(w http.ResponseWriter, r *http.Request, peer *models.Peer, pqCiphertext string, status int) {
	if peer.DeviceID == nil {
		respond.JsonError(w, "active connection has no device identity", http.StatusInternalServerError)
		return
	}
	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.SafeError(w, "failed to load connection server", err, http.StatusInternalServerError)
		return
	}
	wireGuard, configured := enabledServerTransport(server, "wireguard")
	if !configured {
		respond.JsonError(w, "the existing server no longer has WireGuard enabled", http.StatusConflict)
		return
	}
	serverPublicKey := server.PublicKey
	if coreStats, statsErr := CallCoreServerStats(server); statsErr == nil && coreStats.PublicKey != "" {
		serverPublicKey = coreStats.PublicKey
		if server.PublicKey != coreStats.PublicKey {
			server.PublicKey = coreStats.PublicKey
			if updateErr := h.serverRepo.Update(r.Context(), server); updateErr != nil {
				slog.Warn("failed to persist server public key", "server_id", server.ID, "error", updateErr)
			}
		}
	}
	peerIP := peer.AssignedIP
	if index := strings.Index(peerIP, "/"); index != -1 {
		peerIP = peerIP[:index]
	}
	w.Header().Set("Cache-Control", "no-store")
	respond.JsonOK(w, models.ConnectionConfig{
		PeerID:          peer.ID,
		DeviceID:        *peer.DeviceID,
		PeerIP:          peerIP,
		ServerPublicKey: serverPublicKey,
		ServerEndpoint:  wireGuardEndpointForServerHost(wireGuard.Host, wireGuard.Port),
		PresharedKey:    peer.PresharedKey,
		PQKEMCiphertext: pqCiphertext,
		DNS:             h.vpnDNS,
		AllowedIPs:      "0.0.0.0/0, ::/0",
	}, status)
}

func (h *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	// Per-user rate limit: prevent connection-spam / brute-force reconnects.
	if h.connectLimiter != nil && !h.connectLimiter.Allow(user.ID.String()) {
		respond.JsonError(w, "too many connection requests — please wait before trying again", http.StatusTooManyRequests)
		return
	}

	var req ConnectRequest
	if err := decodeStrictJSON(r.Body, &req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.PublicKey == "" {
		respond.JsonError(w, "public_key is required", http.StatusBadRequest)
		return
	}
	if !isValidWGKey(req.PublicKey) {
		respond.JsonError(w, "public_key must be a valid 32-byte base64-encoded WireGuard key", http.StatusBadRequest)
		return
	}
	deviceRequest, err := normalizeDeviceRequest(req.Device, req.DeviceName)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	var device *models.Device
	if deviceRequest.clientInstanceID != nil {
		device, err = h.resolveRegisteredDevice(r.Context(), user.ID, deviceRequest)
		if errors.Is(err, repo.ErrDeviceRevoked) {
			respond.JsonErrorCode(w, "device is revoked", "device_revoked", http.StatusConflict)
			return
		}
		if err != nil {
			respond.SafeError(w, "failed to resolve device identity", err, http.StatusInternalServerError)
			return
		}
	}

	// Recognize durable retries before quota or capacity checks. An unfinished
	// operation must be reconciled rather than duplicated; a finished operation
	// returns the exact session and sensitive material already persisted for it.
	if operation, existingPeer, findErr := h.peerOperationRepo.FindCurrentByKey(r.Context(), user.ID, req.PublicKey); findErr == nil {
		if existingPeer == nil {
			w.Header().Set("Retry-After", "5")
			respond.JsonErrorCode(w, "connection operation is still in progress", "connection_in_progress", http.StatusConflict)
			return
		}
		if device != nil && (existingPeer.DeviceID == nil || *existingPeer.DeviceID != device.ID) {
			respond.JsonErrorCode(w, "public key belongs to another device", "peer_operation_conflict", http.StatusConflict)
			return
		}
		h.respondWithExistingConnection(w, r, existingPeer, operation.PQKEMCiphertext, http.StatusOK)
		return
	} else if !errors.Is(findErr, pgx.ErrNoRows) {
		respond.SafeError(w, "failed to inspect connection operation", findErr, http.StatusInternalServerError)
		return
	}

	// Compatibility for active peers created before operation persistence.
	if existingPeer, err := h.peerRepo.GetActiveByUserAndPublicKey(r.Context(), user.ID, req.PublicKey); err == nil {
		if existingPeer.DeviceID == nil {
			respond.JsonError(w, "active connection has no device identity", http.StatusInternalServerError)
			return
		}
		if device != nil && *existingPeer.DeviceID != device.ID {
			respond.JsonErrorCode(w, "public key belongs to another device", "peer_operation_conflict", http.StatusConflict)
			return
		}
		h.respondWithExistingConnection(w, r, existingPeer, "", http.StatusOK)
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		respond.SafeError(w, "failed to inspect active connection", err, http.StatusInternalServerError)
		return
	}

	// 2. Enforce global user device limit based on plan/quota
	userQuota, err := h.getUserQuota(r.Context(), user)
	if err != nil {
		respond.SafeError(w, "failed to load device quota", err, http.StatusInternalServerError)
		return
	}
	replacesActiveDevice := false
	if device != nil {
		replacesActiveDevice, err = h.deviceRepo.HasActiveSession(r.Context(), user.ID, device.ID)
		if err != nil {
			respond.SafeError(w, "failed to check active device session", err, http.StatusInternalServerError)
			return
		}
	}
	if userQuota.ConnectedDevices >= userQuota.MaxDevices && !replacesActiveDevice {
		respond.JsonErrorCode(w, fmt.Sprintf("device limit reached (%d/%d devices in use on your %s)", userQuota.ConnectedDevices, userQuota.MaxDevices, userQuota.PlanName), "device_limit_reached", http.StatusConflict)
		return
	}

	// 3. Select server (explicit or least loaded)
	var server *models.VPNServer
	if req.ServerID != "" {
		serverID, err := uuid.Parse(req.ServerID)
		if err != nil {
			respond.JsonError(w, "invalid server_id", http.StatusBadRequest)
			return
		}
		s, err := h.serverRepo.GetByID(r.Context(), serverID)
		if err != nil {
			slog.Error("serverRepo.GetByID error", "server_id", serverID, "error", err)
			if errors.Is(err, pgx.ErrNoRows) {
				respond.JsonError(w, "server not found", http.StatusNotFound)
			} else {
				respond.JsonError(w, "failed to get server", http.StatusInternalServerError)
			}
			return
		}
		server = s
	} else {
		s, err := h.serverRepo.LeastLoaded(r.Context())
		if err != nil {
			respond.JsonError(w, "no available servers", http.StatusServiceUnavailable)
			return
		}
		server = s
	}
	_, configured := enabledServerTransport(server, "wireguard")
	if !configured {
		respond.JsonError(w, "selected server does not have WireGuard enabled", http.StatusConflict)
		return
	}

	// 4. Generate post-quantum resistant Pre-Shared Key (PSK) or ML-KEM-768 encapsulation
	var psk string
	var pqCiphertext string
	if req.PQKEMPublicKey != "" {
		var kemErr error
		psk, pqCiphertext, kemErr = vpnCrypto.EncapsulateSharedKey(req.PQKEMPublicKey)
		if kemErr != nil {
			slog.Warn("ML-KEM-768 encapsulation failed, falling back to symmetric PSK", "error", kemErr)
			psk, _ = vpnCrypto.GeneratePresharedKey()
		}
	} else {
		var pskErr error
		psk, pskErr = vpnCrypto.GeneratePresharedKey()
		if pskErr != nil {
			slog.Warn("failed to generate PSK", "error", pskErr)
		}
	}

	operationID := uuid.New()
	beginResult, err := h.peerOperationRepo.BeginConnect(r.Context(), repo.BeginConnectParams{
		OperationID:      operationID,
		UserID:           user.ID,
		Device:           device,
		LegacyDeviceName: deviceRequest.reportedName,
		ServerID:         server.ID,
		PublicKey:        req.PublicKey,
		PresharedKey:     psk,
		PQKEMCiphertext:  pqCiphertext,
		MaxDevices:       userQuota.MaxDevices,
	})
	if err != nil {
		switch {
		case errors.Is(err, repo.ErrConnectionInProgress):
			w.Header().Set("Retry-After", "5")
			respond.JsonErrorCode(w, "connection operation is still in progress", "connection_in_progress", http.StatusConflict)
		case errors.Is(err, repo.ErrDeviceLimitReached):
			respond.JsonErrorCode(w, fmt.Sprintf("device limit reached (%d devices on your %s)", userQuota.MaxDevices, userQuota.PlanName), "device_limit_reached", http.StatusConflict)
		case errors.Is(err, repo.ErrServerCapacity):
			respond.JsonError(w, "server is full or inactive", http.StatusConflict)
		case errors.Is(err, repo.ErrServerPlacement):
			respond.JsonError(w, "server node is not ready for new connections", http.StatusConflict)
		case errors.Is(err, repo.ErrDeviceRevoked):
			respond.JsonErrorCode(w, "device is revoked", "device_revoked", http.StatusConflict)
		case errors.Is(err, repo.ErrPeerOperationConflict):
			respond.JsonErrorCode(w, "public key belongs to another device", "peer_operation_conflict", http.StatusConflict)
		default:
			respond.SafeError(w, "failed to start connection operation", err, http.StatusInternalServerError)
		}
		return
	}
	if beginResult.ExistingPeer != nil {
		pqCiphertext := ""
		if beginResult.Operation != nil {
			pqCiphertext = beginResult.Operation.PQKEMCiphertext
		}
		h.respondWithExistingConnection(w, r, beginResult.ExistingPeer, pqCiphertext, http.StatusOK)
		return
	}
	h.serverRepo.InvalidateCache()
	device = beginResult.Device

	// Peers created before Control persisted operations still have an exact
	// owner in Core (assigned during Core's legacy-state adoption). Capture that
	// owner before applying the replacement so delayed cleanup can never target
	// whichever operation happens to own the key later.
	if beginResult.PreviousPeer != nil && beginResult.Operation.PreviousOperationID == nil {
		previousServer, loadErr := h.serverRepo.GetByID(r.Context(), beginResult.PreviousPeer.ServerID)
		if loadErr != nil {
			_ = h.peerOperationRepo.FailDefinitively(r.Context(), operationID, loadErr)
			h.serverRepo.InvalidateCache()
			respond.SafeError(w, "failed to load previous connection server", loadErr, http.StatusInternalServerError)
			return
		}
		previousStats, observeErr := CallCoreGetPeerStats(previousServer, beginResult.PreviousPeer.PublicKey)
		if coreErrorHasStatus(observeErr, http.StatusNotFound) {
			// The database row is stale and there is no Core peer to clean up.
		} else if observeErr != nil {
			_ = h.peerOperationRepo.FailDefinitively(r.Context(), operationID, observeErr)
			h.serverRepo.InvalidateCache()
			respond.JsonError(w, "failed to verify previous VPN session", http.StatusBadGateway)
			return
		} else {
			previousOperationID, parseErr := uuid.Parse(previousStats.OperationID)
			if parseErr != nil || previousOperationID == uuid.Nil {
				identityErr := errors.New("previous Core peer has an invalid operation identity")
				_ = h.peerOperationRepo.FailDefinitively(r.Context(), operationID, identityErr)
				h.serverRepo.InvalidateCache()
				respond.JsonError(w, "failed to verify previous VPN session", http.StatusBadGateway)
				return
			}
			if setErr := h.peerOperationRepo.SetPreviousOperationID(r.Context(), operationID, previousOperationID); setErr != nil {
				_ = h.peerOperationRepo.FailDefinitively(r.Context(), operationID, setErr)
				h.serverRepo.InvalidateCache()
				respond.SafeError(w, "failed to persist previous connection owner", setErr, http.StatusInternalServerError)
				return
			}
			beginResult.Operation.PreviousOperationID = &previousOperationID
		}
	}

	coreResp, err := CallCoreAddPeer(server, req.PublicKey, operationID.String(), psk)
	if err != nil {
		slog.Error("core add peer error", "error", err)
		var coreError *CoreAPIError
		if errors.As(err, &coreError) && coreError.Status >= 400 && coreError.Status < 500 {
			if failErr := h.peerOperationRepo.FailDefinitively(r.Context(), operationID, err); failErr != nil {
				slog.Error("failed to finalize rejected peer operation", "operation_id", operationID, "error", failErr)
			}
			h.serverRepo.InvalidateCache()
			if coreError.Code == "peer_operation_conflict" {
				respond.JsonErrorCode(w, "peer is owned by another operation", "peer_operation_conflict", http.StatusConflict)
				return
			}
		}
		respond.JsonError(w, "failed to connect to VPN server", http.StatusBadGateway)
		return
	}
	if err := h.peerOperationRepo.MarkCoreApplied(r.Context(), operationID, coreResp.AllowedIP); err != nil {
		slog.Error("failed to persist applied Core operation", "operation_id", operationID, "error", err)
		respond.JsonError(w, "failed to persist connection progress", http.StatusInternalServerError)
		return
	}
	peer, previousPeer, err := h.peerOperationRepo.CompleteConnect(r.Context(), operationID)
	if err != nil {
		if errors.Is(err, repo.ErrAccessRevoked) {
			cleanupErr := CallCoreRemovePeerContext(r.Context(), server, req.PublicKey, operationID.String())
			if cleanupErr == nil {
				cleanupErr = h.peerOperationRepo.CancelDeniedConnect(r.Context(), operationID)
			}
			if cleanupErr != nil {
				h.recordDisconnectFailure(r.Context(), operationID, cleanupErr)
			}
			respond.JsonError(w, "account or device access was revoked", http.StatusForbidden)
			return
		}
		slog.Error("failed to complete peer operation", "operation_id", operationID, "error", err)
		respond.JsonError(w, "failed to save connection", http.StatusInternalServerError)
		return
	}
	h.serverRepo.InvalidateCache()

	if previousPeer != nil && previousPeer.IsActive {
		if beginResult.Operation.PreviousOperationID == nil {
			// The preflight observation already proved the legacy Core peer absent.
			_ = h.peerOperationRepo.CompleteCleanup(r.Context(), operationID)
		} else {
			previousServer, loadErr := h.serverRepo.GetByID(r.Context(), previousPeer.ServerID)
			if loadErr != nil {
				_ = h.peerOperationRepo.MarkCleanupPending(r.Context(), operationID, loadErr)
			} else {
				cleanupErr := CallCoreRemovePeer(previousServer, previousPeer.PublicKey, beginResult.Operation.PreviousOperationID.String())
				if cleanupErr != nil {
					slog.Error("replaced peer cleanup is pending", "operation_id", operationID, "peer_id", previousPeer.ID, "error", cleanupErr)
					_ = h.peerOperationRepo.MarkCleanupPending(r.Context(), operationID, cleanupErr)
				} else if completeErr := h.peerOperationRepo.CompleteCleanup(r.Context(), operationID); completeErr != nil {
					slog.Error("failed to finalize replaced peer cleanup", "operation_id", operationID, "peer_id", previousPeer.ID, "error", completeErr)
				}
			}
		}
	}

	h.attachPeerToMeshSessions(r.Context(), user.ID, peer)

	h.auditRepo.Log(r.Context(), &user.ID, "peer.connect",
		map[string]interface{}{
			"operation_id": operationID,
			"peer_id":      peer.ID,
			"device_id":    device.ID,
			"server_id":    server.ID,
			"ip":           peer.AssignedIP,
			"device_name":  device.ReportedName,
			"psk_enabled":  psk != "",
		}, r.RemoteAddr)

	h.respondWithExistingConnection(w, r, peer, pqCiphertext, http.StatusCreated)
}

func (h *Handler) Disconnect(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil {
		respond.JsonError(w, "peer not found", http.StatusNotFound)
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
		return
	}

	outcome, err := h.disconnectPeer(r.Context(), peerID)
	if errors.Is(err, repo.ErrConnectionInProgress) {
		w.Header().Set("Retry-After", "5")
		respond.JsonErrorCode(w, "connection operation is still in progress", "connection_in_progress", http.StatusConflict)
		return
	}
	if err != nil {
		slog.Error("failed to schedule disconnect", "peer_id", peerID, "error", err)
		respond.JsonError(w, "failed to disconnect peer", http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &user.ID, "peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "server_id": peer.ServerID}, r.RemoteAddr)

	respondDisconnect(w, outcome, "disconnect_pending")
}

func (h *Handler) ExportConfig(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByIDForPresharedKeyExport(r.Context(), peerID, user.ID, IsAdmin(user))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "peer not found", http.StatusNotFound)
		} else {
			respond.SafeError(w, "failed to load connection material", err, http.StatusInternalServerError)
		}
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
		return
	}
	if !peer.IsActive {
		respond.JsonError(w, "connection is inactive", http.StatusConflict)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	ensureServerPublicKey(server)
	conf := h.buildWGConfig(peer, server)

	safeName := sanitizeDeviceName(peer.DeviceName)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="wg-%s.conf"`, safeName))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(conf))
}

func (h *Handler) ExportQR(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByIDForPresharedKeyExport(r.Context(), peerID, user.ID, IsAdmin(user))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "peer not found", http.StatusNotFound)
		} else {
			respond.SafeError(w, "failed to load connection material", err, http.StatusInternalServerError)
		}
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
		return
	}
	if !peer.IsActive {
		respond.JsonError(w, "connection is inactive", http.StatusConflict)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	ensureServerPublicKey(server)
	conf := h.buildWGConfig(peer, server)

	png, err := qrcode.Encode(conf, qrcode.Medium, 512)
	if err != nil {
		slog.Error("qr generation error", "error", err)
		respond.JsonError(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="wg-%s.png"`, sanitizeDeviceName(peer.DeviceName)))
	w.WriteHeader(http.StatusOK)
	w.Write(png)
}

// ProxyCredentials generates a short-lived token with audience aud=vpn-proxy for browser extensions
func (h *Handler) ProxyCredentials(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	servers, err := h.serverRepo.ListActive(r.Context())
	if err != nil {
		respond.SafeError(w, "failed to list servers", err, http.StatusInternalServerError)
		return
	}

	type proxyEndpoint struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		CountryCode string `json:"country_code"`
		Location    string `json:"location"`
	}

	endpoints := make([]proxyEndpoint, 0)
	for _, s := range servers {
		if transport, ok := enabledServerTransport(&s, "proxy"); ok {
			endpoints = append(endpoints, proxyEndpoint{
				Host:        transport.Host,
				Port:        transport.Port,
				CountryCode: s.CountryCode,
				Location:    s.Location,
			})
		}
	}

	// Scoped proxy token with 15-minute validity signed with HMAC-SHA256 (aud=vpn-proxy)
	proxyTokenStr := proxytoken.Generate(user.ID, h.credentialSigningSecret, proxytoken.DefaultTTL)

	respond.JsonOK(w, map[string]interface{}{
		"proxy_token":     proxyTokenStr,
		"expires_in":      int(proxytoken.DefaultTTL.Seconds()),
		"proxy_endpoints": endpoints,
	}, http.StatusOK)
}

// TunnelCredentials issues a short-lived credential for an active device. It
// does not enable a transport by itself; clients must use a server-advertised capability.
func (h *Handler) TunnelCredentials(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	var req struct {
		PeerID string `json:"peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	peerID, err := uuid.Parse(req.PeerID)
	if err != nil {
		respond.JsonError(w, "invalid peer_id", http.StatusBadRequest)
		return
	}
	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil || peer.UserID != user.ID || !peer.IsActive {
		respond.JsonError(w, "active device not found", http.StatusNotFound)
		return
	}
	token := proxytoken.GenerateTunnel(proxytoken.TunnelClaims{UserID: user.ID, DeviceID: peer.ID, ServerID: peer.ServerID}, h.credentialSigningSecret, proxytoken.DefaultTTL)
	respond.JsonOK(w, map[string]interface{}{"tunnel_token": token, "expires_in": int(proxytoken.DefaultTTL.Seconds())}, http.StatusOK)
}

// ensureServerPublicKey fetches the real WireGuard public key from the core
// and updates the server record if it differs from what is stored.
func ensureServerPublicKey(server *models.VPNServer) {
	stats, err := CallCoreServerStats(server)
	if err != nil {
		slog.Warn("could not fetch core stats for public key", "server_id", server.ID, "error", err)
		return
	}
	if stats.PublicKey != "" && stats.PublicKey != server.PublicKey {
		slog.Info("updating server public key from core", "server_id", server.ID)
		server.PublicKey = stats.PublicKey
	}
}

func (h *Handler) buildWGConfig(peer *models.Peer, server *models.VPNServer) string {
	// Use Endpoint if set (public-facing host), otherwise fall back to Host
	epHost := server.Endpoint
	if epHost == "" {
		epHost = server.Host
	}
	endpoint := wireGuardEndpointForServerHost(epHost, server.WGPort)

	// Normalize AssignedIP: strip any duplicate /32 suffix from old DB rows,
	// then ensure exactly one /32 suffix is present.
	assignedIP := peer.AssignedIP
	for strings.HasSuffix(assignedIP, "/32/32") {
		assignedIP = strings.TrimSuffix(assignedIP, "/32")
	}
	if !strings.Contains(assignedIP, "/") {
		assignedIP += "/32"
	}

	return fmt.Sprintf(`[Interface]
PrivateKey = <YOUR_PRIVATE_KEY>
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, assignedIP, h.vpnDNS, server.PublicKey, endpoint)
}

func (h *Handler) ListMyConnections(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	peers, err := h.peerRepo.ListActiveByUser(r.Context(), user.ID)
	if err != nil {
		slog.Error("list connections error", "error", err)
		respond.JsonError(w, "failed to list connections", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, peers, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// User audit
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) MyAuditLogs(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	logs, err := h.auditRepo.ListByUser(r.Context(), user.ID, 50, 0)
	if err != nil {
		slog.Error("list audit logs error", "error", err)
		respond.JsonError(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, logs, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Admin API
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) AdminDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	totalUsers, _ := h.userRepo.Count(ctx)
	totalServers, activeServers, _ := h.serverRepo.Count(ctx)
	totalPeers, activePeers, _ := h.peerRepo.CountAll(ctx)
	bytesSent, bytesRecv, _ := h.peerRepo.TotalTraffic(ctx)

	stats := models.AdminStats{
		TotalUsers:     totalUsers,
		TotalServers:   totalServers,
		ActiveServers:  activeServers,
		TotalPeers:     totalPeers,
		ActivePeers:    activePeers,
		TotalBytesSent: bytesSent,
		TotalBytesRecv: bytesRecv,
	}
	respond.JsonOK(w, stats, http.StatusOK)
}

func (h *Handler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	users, err := h.userRepo.List(r.Context(), limit, offset)
	if err != nil {
		slog.Error("admin list users error", "error", err)
		respond.JsonError(w, "failed to list users", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, users, http.StatusOK)
}

func (h *Handler) AdminGetUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), id)
	if err != nil {
		respond.JsonError(w, "user not found", http.StatusNotFound)
		return
	}

	peers, _ := h.peerRepo.ListByUser(r.Context(), id)

	respond.JsonOK(w, map[string]interface{}{
		"user":  user,
		"peers": peers,
	}, http.StatusOK)
}

type AdminCreateUserRequest struct {
	AuthentikUID string   `json:"authentik_uid"`
	Email        string   `json:"email"`
	DisplayName  string   `json:"display_name"`
	Groups       []string `json:"groups"`
}

func (h *Handler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req AdminCreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.AuthentikUID == "" || req.Email == "" {
		respond.JsonError(w, "authentik_uid and email are required", http.StatusBadRequest)
		return
	}

	user := &models.User{
		AuthentikUID: req.AuthentikUID,
		Email:        req.Email,
		DisplayName:  req.DisplayName,
		Groups:       req.Groups,
	}
	if user.Groups == nil {
		user.Groups = []string{}
	}

	if err := h.userRepo.Create(r.Context(), user); err != nil {
		slog.Error("admin create user error", "error", err)
		respond.JsonError(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.create",
		map[string]interface{}{"target_user_id": user.ID}, r.RemoteAddr)

	respond.JsonOK(w, user, http.StatusCreated)
}

type AdminUpdateUserRequest struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`
}

func (h *Handler) AdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), id)
	if err != nil {
		respond.JsonError(w, "user not found", http.StatusNotFound)
		return
	}

	var req AdminUpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Email != "" {
		user.Email = req.Email
	}
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.Groups != nil {
		user.Groups = req.Groups
	}

	if err := h.userRepo.Update(r.Context(), user); err != nil {
		slog.Error("admin update user error", "user_id", user.ID, "error", err)
		respond.JsonError(w, "failed to update user", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.update",
		map[string]interface{}{"target_user_id": id}, r.RemoteAddr)

	respond.JsonOK(w, user, http.StatusOK)
}

func (h *Handler) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	admin := auth.GetUser(r)
	if admin.ID == id {
		respond.JsonError(w, "cannot delete your own account", http.StatusForbidden)
		return
	}

	if err := h.userRepo.DeleteIfDrained(r.Context(), id); err != nil {
		if errors.Is(err, repo.ErrActiveDevicesMustBeDisconnected) {
			respond.JsonErrorCode(w, "active devices must be disconnected before deleting the user", "active_devices_must_be_disconnected", http.StatusConflict)
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "user not found", http.StatusNotFound)
			return
		}
		slog.Error("admin delete user error", "user_id", id, "error", err)
		respond.JsonError(w, "failed to delete user", http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.delete",
		map[string]interface{}{"target_user_id": id}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"deleted": id.String()}, http.StatusOK)
}

type BanRequest struct {
	Reason string `json:"reason"`
}

func (h *Handler) AdminBanUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	admin := auth.GetUser(r)
	if admin.ID == id {
		respond.JsonError(w, "cannot ban your own account", http.StatusForbidden)
		return
	}

	var req BanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.userRepo.Ban(r.Context(), id, req.Reason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "user not found", http.StatusNotFound)
			return
		}
		slog.Error("admin ban user error", "user_id", id, "error", err)
		respond.JsonError(w, "failed to ban user", http.StatusInternalServerError)
		return
	}

	cleanupPending := false
	peers, listErr := h.peerRepo.ListActiveByUser(r.Context(), id)
	if listErr != nil {
		cleanupPending = true
		slog.Error("banned user cleanup could not list sessions", "user_id", id, "error", listErr)
	} else {
		for index := range peers {
			outcome, disconnectErr := h.disconnectPeer(r.Context(), peers[index].ID)
			if disconnectErr != nil || !outcome.Converged {
				cleanupPending = true
				if disconnectErr != nil && !errors.Is(disconnectErr, repo.ErrConnectionInProgress) {
					slog.Error("banned user cleanup could not be scheduled", "user_id", id, "peer_id", peers[index].ID, "error", disconnectErr)
				}
			}
		}
	}
	if liveOperation, operationErr := h.peerOperationRepo.HasLiveByUser(r.Context(), id); operationErr != nil {
		cleanupPending = true
		slog.Error("banned user cleanup state could not be verified", "user_id", id, "error", operationErr)
	} else if liveOperation {
		cleanupPending = true
	}

	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.ban",
		map[string]interface{}{"target_user_id": id, "reason": req.Reason}, r.RemoteAddr)

	if cleanupPending {
		w.Header().Set("Retry-After", "5")
		respondStatus(w, "ban_cleanup_pending", http.StatusAccepted)
		return
	}
	respondStatus(w, "banned", http.StatusOK)
}

func (h *Handler) AdminUnbanUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid user id", http.StatusBadRequest)
		return
	}

	if err := h.userRepo.Unban(r.Context(), id); err != nil {
		slog.Error("admin unban user error", "user_id", id, "error", err)
		respond.JsonError(w, "failed to unban user", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.unban",
		map[string]interface{}{"target_user_id": id}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "unbanned"}, http.StatusOK)
}

type CreateServerRequest struct {
	Name        string             `json:"name"`
	Host        string             `json:"host"`
	Endpoint    string             `json:"endpoint"`
	Port        int                `json:"port"`
	WGPort      int                `json:"wg_port"`
	PublicKey   string             `json:"public_key"`
	Location    string             `json:"location"`
	CountryCode string             `json:"country_code"`
	MaxPeers    int                `json:"max_peers"`
	Transports  []TransportRequest `json:"transports"`
}

func (h *Handler) AdminListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := h.serverRepo.ListAll(r.Context())
	if err != nil {
		slog.Error("admin list servers error", "error", err)
		respond.JsonError(w, "failed to list servers", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, servers, http.StatusOK)
}

func (h *Handler) AdminListNodeIdentities(w http.ResponseWriter, r *http.Request) {
	if h.nodeVerifier == nil {
		respond.JsonError(w, "node identity registry is unavailable", http.StatusServiceUnavailable)
		return
	}
	identities, err := h.nodeVerifier.List(r.Context())
	if err != nil {
		respond.JsonError(w, "failed to list node identities", http.StatusServiceUnavailable)
		return
	}
	respond.JsonOK(w, identities, http.StatusOK)
}

func (h *Handler) AdminRegisterNodeIdentity(w http.ResponseWriter, r *http.Request) {
	if h.nodeVerifier == nil {
		respond.JsonError(w, "node identity registry is unavailable", http.StatusServiceUnavailable)
		return
	}
	var request struct {
		NodeID    string `json:"node_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := h.nodeVerifier.Register(r.Context(), request.NodeID, request.PublicKey); err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.node-identity.register", map[string]interface{}{"node_id": request.NodeID}, r.RemoteAddr)
	respond.JsonOK(w, map[string]string{"node_id": request.NodeID, "status": "registered"}, http.StatusCreated)
}

func (h *Handler) AdminRevokeNodeIdentity(w http.ResponseWriter, r *http.Request) {
	h.changeNodeIdentityRevocation(w, r, true)
}

func (h *Handler) AdminRestoreNodeIdentity(w http.ResponseWriter, r *http.Request) {
	h.changeNodeIdentityRevocation(w, r, false)
}

func (h *Handler) changeNodeIdentityRevocation(w http.ResponseWriter, r *http.Request, revoked bool) {
	if h.nodeVerifier == nil {
		respond.JsonError(w, "node identity registry is unavailable", http.StatusServiceUnavailable)
		return
	}
	nodeID := strings.TrimSpace(chi.URLParam(r, "nodeID"))
	if nodeID == "" {
		respond.JsonError(w, "node_id is required", http.StatusBadRequest)
		return
	}
	status := "restored"
	action := "admin.node-identity.restore"
	var err error
	if revoked {
		err = h.nodeVerifier.Revoke(r.Context(), nodeID)
		status = "revoked"
		action = "admin.node-identity.revoke"
	} else {
		err = h.nodeVerifier.Restore(r.Context(), nodeID)
	}
	if err != nil {
		respond.JsonError(w, "failed to update node identity", http.StatusServiceUnavailable)
		return
	}
	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, action, map[string]interface{}{"node_id": nodeID}, r.RemoteAddr)
	respond.JsonOK(w, map[string]string{"node_id": nodeID, "status": status}, http.StatusOK)
}

func (h *Handler) AdminCreateServer(w http.ResponseWriter, r *http.Request) {
	var req CreateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Host == "" || req.PublicKey == "" {
		respond.JsonError(w, "name, host and public_key are required", http.StatusBadRequest)
		return
	}
	if req.Port == 0 {
		req.Port = defaultAdminServerPort(h.coreAllowLoopback)
	}
	if req.WGPort == 0 {
		req.WGPort = 51820
	}
	if req.MaxPeers == 0 {
		req.MaxPeers = 250
	}

	// Validate optional WireGuard endpoint (public IP or hostname used in client configs).
	if req.Endpoint != "" {
		if err := validateServerEndpoint(req.Endpoint); err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	normalizedHost, normalizedPort, err := normalizeAdminServerHost(req.Host, req.Port)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Host = normalizedHost
	req.Port = normalizedPort
	if h.appEnv == "production" && !h.coreAllowLoopback && isLoopbackServerHost(req.Host) {
		respond.JsonError(w, "loopback hosts (localhost/127.0.0.1/::1) are not allowed in production — set CORE_ALLOW_INSECURE_HTTP=true to override", http.StatusBadRequest)
		return
	}

	server := &models.VPNServer{
		Name:        req.Name,
		Host:        req.Host,
		Endpoint:    req.Endpoint,
		Port:        req.Port,
		WGPort:      req.WGPort,
		PublicKey:   req.PublicKey,
		Location:    req.Location,
		CountryCode: req.CountryCode,
		MaxPeers:    req.MaxPeers,
		IsActive:    true,
	}
	if req.Transports == nil {
		respond.JsonError(w, "transports is required", http.StatusBadRequest)
		return
	}
	transports, err := validateTransportRequests(req.Transports, h.appEnv == "production", h.coreAllowLoopback)
	if err != nil {
		respond.JsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if hasEnabledCertificateTransport(transports) && h.clientCertificateCA == nil {
		respond.JsonErrorCode(w, "client PKI must be configured before enabling OpenVPN or IKEv2", clientPKIUnavailableCode, http.StatusConflict)
		return
	}

	if err := h.serverRepo.CreateWithTransports(r.Context(), server, transports); err != nil {
		slog.Error("admin create server error", "error", err)
		respond.JsonError(w, "failed to create server", http.StatusInternalServerError)
		return
	}
	server.SetTransports(transports)
	server.ApplyCapabilities()

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.create",
		map[string]interface{}{"server_id": server.ID, "name": server.Name}, r.RemoteAddr)

	respond.JsonOK(w, server, http.StatusCreated)
}

type UpdateServerRequest struct {
	Name        string              `json:"name"`
	Host        string              `json:"host"`
	Endpoint    string              `json:"endpoint"`
	Port        int                 `json:"port"`
	WGPort      int                 `json:"wg_port"`
	PublicKey   string              `json:"public_key"`
	Location    string              `json:"location"`
	CountryCode string              `json:"country_code"`
	MaxPeers    int                 `json:"max_peers"`
	IsActive    *bool               `json:"is_active"`
	Transports  *[]TransportRequest `json:"transports"`
}

func (h *Handler) AdminUpdateServer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	server, err := h.serverRepo.GetByID(r.Context(), id)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	var req UpdateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Name != "" {
		server.Name = req.Name
	}
	// Endpoint may be cleared (set to "") intentionally, so always update it.
	// Validate if non-empty.
	if req.Endpoint != "" {
		if err := validateServerEndpoint(req.Endpoint); err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	server.Endpoint = req.Endpoint
	if req.Host != "" || req.Port != 0 {
		hostInput := server.Host
		if req.Host != "" {
			hostInput = req.Host
		}
		portInput := server.Port
		if req.Port != 0 {
			portInput = req.Port
		}

		normalizedHost, normalizedPort, err := normalizeAdminServerHost(hostInput, portInput)
		if err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if h.appEnv == "production" && !h.coreAllowLoopback && isLoopbackServerHost(normalizedHost) {
			respond.JsonError(w, "loopback hosts (localhost/127.0.0.1/::1) are not allowed in production — set CORE_ALLOW_INSECURE_HTTP=true to override", http.StatusBadRequest)
			return
		}

		server.Host = normalizedHost
		server.Port = normalizedPort
	}
	if req.WGPort != 0 {
		server.WGPort = req.WGPort
	}
	if req.PublicKey != "" {
		server.PublicKey = req.PublicKey
	}
	if req.Location != "" {
		server.Location = req.Location
	}
	if req.CountryCode != "" {
		server.CountryCode = req.CountryCode
	}
	if req.MaxPeers != 0 {
		server.MaxPeers = req.MaxPeers
	}
	if req.IsActive != nil {
		server.IsActive = *req.IsActive
		if server.IsActive {
			server.DrainingAt = nil
		}
	}
	var transports []models.TransportCapability
	if req.Transports != nil {
		transports, err = validateTransportRequests(*req.Transports, h.appEnv == "production", h.coreAllowLoopback)
		if err != nil {
			respond.JsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if hasEnabledCertificateTransport(transports) && h.clientCertificateCA == nil {
			respond.JsonErrorCode(w, "client PKI must be configured before enabling OpenVPN or IKEv2", clientPKIUnavailableCode, http.StatusConflict)
			return
		}
	}

	if err := h.serverRepo.UpdateWithTransports(r.Context(), server, transports, req.Transports != nil); err != nil {
		slog.Error("admin update server error", "server_id", server.ID, "error", err)
		respond.JsonError(w, "failed to update server", http.StatusInternalServerError)
		return
	}
	if req.Transports != nil {
		server.SetTransports(transports)
	}
	server.ApplyCapabilities()

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.update",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	respond.JsonOK(w, server, http.StatusOK)
}

func (h *Handler) AdminDeleteServer(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid server id", http.StatusBadRequest)
		return
	}

	if err := h.serverRepo.DrainAndDelete(r.Context(), id); err != nil {
		if errors.Is(err, repo.ErrServerNotDrained) {
			respond.JsonErrorCode(w, "server is draining and still has active sessions or operations", "server_not_drained", http.StatusConflict)
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			respond.JsonError(w, "server not found", http.StatusNotFound)
			return
		}
		slog.Error("admin delete server error", "server_id", id, "error", err)
		respond.JsonError(w, "failed to delete server", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.delete",
		map[string]interface{}{"server_id": id}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"deleted": id.String()}, http.StatusOK)
}

func (h *Handler) AdminListPeers(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	peers, err := h.peerRepo.ListAll(r.Context(), limit, offset)
	if err != nil {
		slog.Error("admin list peers error", "error", err)
		respond.JsonError(w, "failed to list peers", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, peers, http.StatusOK)
}

func (h *Handler) AdminForceDisconnectPeer(w http.ResponseWriter, r *http.Request) {
	peerID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid peer id", http.StatusBadRequest)
		return
	}

	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil {
		respond.JsonError(w, "peer not found", http.StatusNotFound)
		return
	}

	outcome, err := h.disconnectPeer(r.Context(), peerID)
	if errors.Is(err, repo.ErrConnectionInProgress) {
		w.Header().Set("Retry-After", "5")
		respond.JsonErrorCode(w, "connection operation is still in progress", "connection_in_progress", http.StatusConflict)
		return
	}
	if err != nil {
		slog.Error("admin disconnect could not be scheduled", "peer_id", peerID, "error", err)
		respond.JsonError(w, "failed to disconnect peer", http.StatusInternalServerError)
		return
	}

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "user_id": peer.UserID}, r.RemoteAddr)

	respondDisconnect(w, outcome, "disconnect_pending")
}

func (h *Handler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, offset := paginationParams(r)
	action := r.URL.Query().Get("action")
	logs, err := h.auditRepo.ListAll(r.Context(), limit, offset, action)
	if err != nil {
		slog.Error("admin list audit logs error", "error", err)
		respond.JsonError(w, "failed to list audit logs", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, logs, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

func IsAdmin(user *models.User) bool {
	if user == nil {
		return false
	}
	for _, g := range user.Groups {
		switch g {
		case "vpn-admins", "admins", "authentik Admins":
			return true
		}
	}
	return false
}

func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r)
		if !IsAdmin(user) {
			respond.JsonError(w, "admin access required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func paginationParams(r *http.Request) (int, int) {
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 200 {
		limit = l
	}
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
	}
	return limit, offset
}
