package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	qrcode "github.com/skip2/go-qrcode"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	vpnCrypto "github.com/goastian/midori-vpn-core/internal/crypto"
	"github.com/goastian/midori-vpn-core/internal/models"
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
// hostname-or-IP string (not a URL scheme, no path, no query).
func validateServerEndpoint(ep string) error {
	if len(ep) > 253 {
		return fmt.Errorf("endpoint is too long")
	}
	if !endpointHostRe.MatchString(ep) {
		return fmt.Errorf("endpoint must be a valid hostname or IP address (no scheme, path, or query)")
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
	userRepo          *repo.UserRepo
	serverRepo        *repo.ServerRepo
	peerRepo          *repo.PeerRepo
	meshRepo          *repo.MeshRepo
	auditRepo         *repo.AuditRepo
	wgMgr             *wg.Manager
	hub               *WSHub
	maxDevicesPerUser int
	appEnv            string
	coreAllowLoopback bool
	vpnDNS            string
	connectLimiter    *userRateLimiter // per-user rate limit for the /connect endpoint
}

func NewHandler(pool *pgxpool.Pool, cfg *config.Config) *Handler {
	return NewHandlerWithMesh(pool, cfg, nil, nil)
}

func NewHandlerWithMesh(pool *pgxpool.Pool, cfg *config.Config, wgMgr *wg.Manager, hub *WSHub) *Handler {
	h := &Handler{
		userRepo:          repo.NewUserRepo(pool),
		serverRepo:        repo.NewServerRepo(pool),
		peerRepo:          repo.NewPeerRepo(pool),
		meshRepo:          repo.NewMeshRepo(pool),
		auditRepo:         repo.NewAuditRepo(pool),
		wgMgr:             wgMgr,
		hub:               hub,
		maxDevicesPerUser: cfg.MaxDevicesPerUser,
		appEnv:            cfg.AppEnv,
		coreAllowLoopback: cfg.CoreAllowHTTP,
		vpnDNS:            cfg.VpnDNS,
	}
	if cfg.ConnectRateLimitRPS > 0 {
		h.connectLimiter = newUserRateLimiter(cfg.ConnectRateLimitRPS, cfg.ConnectRateLimitBurst)
	}
	return h
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

// ═══════════════════════════════════════════════════════════════════════════
// User profile
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if user == nil {
		respond.JsonError(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	respond.JsonOK(w, user, http.StatusOK)
}

// ═══════════════════════════════════════════════════════════════════════════
// Keypair generation (browser-side)
// ═══════════════════════════════════════════════════════════════════════════

func (h *Handler) GenerateKeypair(w http.ResponseWriter, r *http.Request) {
	kp, err := vpnCrypto.GenerateKeypair()
	if err != nil {
		slog.Error("keypair generation error", "error", err)
		respond.JsonError(w, "failed to generate keypair", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, kp, http.StatusCreated)
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

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	ServerID   string `json:"server_id"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name"`
}

func (h *Handler) Connect(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	// Per-user rate limit: prevent connection-spam / brute-force reconnects.
	if h.connectLimiter != nil && !h.connectLimiter.Allow(user.ID.String()) {
		respond.JsonError(w, "too many connection requests — please wait before trying again", http.StatusTooManyRequests)
		return
	}

	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	req.DeviceName = sanitizeDeviceName(req.DeviceName)

	// 1b. Idempotency: if the same public key is already active for this user,
	// return the existing allocation instead of treating it as a new device.
	// This prevents "device limit reached" errors caused by duplicate connect
	// attempts (e.g. rapid retries, race conditions in the desktop client).
	if existingPeer, err := h.peerRepo.GetActiveByUserAndPublicKey(r.Context(), user.ID, req.PublicKey); err == nil {
		existingServer, sErr := h.serverRepo.GetByID(r.Context(), existingPeer.ServerID)
		if sErr == nil {
			serverPubKey := existingServer.PublicKey
			if coreStats, statsErr := CallCoreServerStats(existingServer); statsErr == nil && coreStats.PublicKey != "" {
				serverPubKey = coreStats.PublicKey
			}
			peerIPAddr := existingPeer.AssignedIP
			if idx := strings.Index(peerIPAddr, "/"); idx != -1 {
				peerIPAddr = peerIPAddr[:idx]
			}
			epHost := existingServer.Endpoint
			if epHost == "" {
				epHost = existingServer.Host
			}
			respond.JsonOK(w, models.ConnectionConfig{
				PeerID:          existingPeer.ID,
				PeerIP:          peerIPAddr,
				ServerPublicKey: serverPubKey,
				ServerEndpoint:  wireGuardEndpointForServerHost(epHost, existingServer.WGPort),
				DNS:             h.vpnDNS,
				AllowedIPs:      "0.0.0.0/0, ::/0",
			}, http.StatusOK)
			return
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		slog.Error("idempotency check error", "error", err)
		// Non-fatal: continue to normal flow.
	}

	// 2. Enforce device limit
	if h.maxDevicesPerUser > 0 {
		activeCount, err := h.peerRepo.CountByUser(r.Context(), user.ID)
		if err != nil {
			slog.Error("count devices error", "error", err)
			respond.JsonError(w, "failed to check device limit", http.StatusInternalServerError)
			return
		}
		if activeCount >= h.maxDevicesPerUser {
			respond.JsonError(w, fmt.Sprintf("device limit reached (max %d)", h.maxDevicesPerUser), http.StatusConflict)
			return
		}
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
			respond.JsonError(w, "server not found", http.StatusNotFound)
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

	// 3b. Atomically reserve a slot (prevents TOCTOU race on capacity)
	reserved, err := h.serverRepo.ReserveSlot(r.Context(), server.ID)
	if err != nil {
		slog.Error("reserve slot error", "error", err)
		respond.JsonError(w, "failed to reserve server slot", http.StatusInternalServerError)
		return
	}
	if !reserved {
		respond.JsonError(w, "server is full or inactive", http.StatusConflict)
		return
	}
	// Ensure slot is released if anything downstream fails
	slotReleased := false
	defer func() {
		if !slotReleased {
			_ = h.serverRepo.UpdatePeerCount(r.Context(), server.ID, -1)
		}
	}()

	// 4+5. Call vpn-core to add peer (core assigns IP from pool)
	coreResp, err := CallCoreAddPeer(server, req.PublicKey)
	if err != nil {
		slog.Error("core add peer error", "error", err)
		respond.JsonError(w, "failed to connect to VPN server", http.StatusBadGateway)
		return
	}

	// 7. Save peer in DB
	peer := &models.Peer{
		UserID:     user.ID,
		ServerID:   server.ID,
		PublicKey:  req.PublicKey,
		AssignedIP: coreResp.AllowedIP,
		DeviceName: req.DeviceName,
	}
	if err := h.peerRepo.Create(r.Context(), peer); err != nil {
		_ = CallCoreRemovePeer(server, req.PublicKey)
		slog.Error("create peer error", "error", err)
		respond.JsonError(w, "failed to save connection", http.StatusInternalServerError)
		return
	}

	slotReleased = true // slot is now owned by the peer record
	h.attachPeerToMeshSessions(r.Context(), user.ID, peer)

	h.auditRepo.Log(r.Context(), &user.ID, "peer.connect",
		map[string]interface{}{
			"peer_id":     peer.ID,
			"server_id":   server.ID,
			"ip":          peer.AssignedIP,
			"device_name": req.DeviceName,
		}, r.RemoteAddr)

	// 8. Fetch the real WireGuard public key from the core
	serverPubKey := server.PublicKey
	coreStats, err := CallCoreServerStats(server)
	if err != nil {
		slog.Warn("could not fetch core stats for server public key", "server_id", server.ID, "error", err)
	} else if coreStats.PublicKey != "" {
		serverPubKey = coreStats.PublicKey
		if server.PublicKey != coreStats.PublicKey {
			server.PublicKey = coreStats.PublicKey
			if updateErr := h.serverRepo.Update(r.Context(), server); updateErr != nil {
				slog.Warn("failed to persist server public key", "server_id", server.ID, "error", updateErr)
			}
		}
	}

	// 9. Return full WireGuard config
	// PeerIP: strip CIDR mask so the frontend can safely append /32 without doubling.
	peerIPAddr := coreResp.AllowedIP
	if idx := strings.Index(peerIPAddr, "/"); idx != -1 {
		peerIPAddr = peerIPAddr[:idx]
	}
	// ServerEndpoint: prefer the public Endpoint field, fall back to Host.
	epHostConnect := server.Endpoint
	if epHostConnect == "" {
		epHostConnect = server.Host
	}
	config := models.ConnectionConfig{
		PeerID:          peer.ID,
		PeerIP:          peerIPAddr,
		ServerPublicKey: serverPubKey,
		ServerEndpoint:  wireGuardEndpointForServerHost(epHostConnect, server.WGPort),
		DNS:             h.vpnDNS,
		AllowedIPs:      "0.0.0.0/0, ::/0",
	}

	respond.JsonOK(w, config, http.StatusCreated)
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

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err == nil {
		_ = CallCoreRemovePeer(server, peer.PublicKey)
		_ = h.serverRepo.UpdatePeerCount(r.Context(), peer.ServerID, -1)
	}

	h.detachPeerFromMeshSessions(r.Context(), peer)
	_ = h.peerRepo.Deactivate(r.Context(), peerID)

	h.auditRepo.Log(r.Context(), &user.ID, "peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "server_id": peer.ServerID}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "disconnected"}, http.StatusOK)
}

func (h *Handler) DeleteConnection(w http.ResponseWriter, r *http.Request) {
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

	// Remove from WireGuard if the peer is active
	if peer.IsActive {
		if server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID); err == nil {
			_ = CallCoreRemovePeer(server, peer.PublicKey)
			_ = h.serverRepo.UpdatePeerCount(r.Context(), peer.ServerID, -1)
		}
	}
	h.detachPeerFromMeshSessions(r.Context(), peer)

	if err := h.peerRepo.Delete(r.Context(), peerID); err != nil {
		respond.JsonError(w, "failed to delete device", http.StatusInternalServerError)
		return
	}

	h.auditRepo.Log(r.Context(), &user.ID, "peer.delete",
		map[string]interface{}{"peer_id": peerID, "server_id": peer.ServerID}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

func (h *Handler) ExportConfig(w http.ResponseWriter, r *http.Request) {
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

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err != nil {
		respond.JsonError(w, "server not found", http.StatusNotFound)
		return
	}

	ensureServerPublicKey(server)
	conf := h.buildWGConfig(peer, server)

	safeName := sanitizeDeviceName(peer.DeviceName)
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

	peer, err := h.peerRepo.GetByID(r.Context(), peerID)
	if err != nil {
		respond.JsonError(w, "peer not found", http.StatusNotFound)
		return
	}

	if peer.UserID != user.ID && !IsAdmin(user) {
		respond.JsonError(w, "not your peer", http.StatusForbidden)
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

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="wg-%s.png"`, sanitizeDeviceName(peer.DeviceName)))
	w.WriteHeader(http.StatusOK)
	w.Write(png)
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
	peers, err := h.peerRepo.ListByUser(r.Context(), user.ID)
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

	if err := h.userRepo.Delete(r.Context(), id); err != nil {
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
		slog.Error("admin ban user error", "user_id", id, "error", err)
		respond.JsonError(w, "failed to ban user", http.StatusInternalServerError)
		return
	}

	// Disconnect all active peers for banned user
	peers, _ := h.peerRepo.ListByUser(r.Context(), id)
	for _, p := range peers {
		if !p.IsActive {
			continue
		}
		server, err := h.serverRepo.GetByID(r.Context(), p.ServerID)
		if err == nil {
			_ = CallCoreRemovePeer(server, p.PublicKey)
			_ = h.serverRepo.UpdatePeerCount(r.Context(), p.ServerID, -1)
		}
		h.detachPeerFromMeshSessions(r.Context(), &p)
		_ = h.peerRepo.Deactivate(r.Context(), p.ID)
	}

	h.auditRepo.Log(r.Context(), &admin.ID, "admin.user.ban",
		map[string]interface{}{"target_user_id": id, "reason": req.Reason}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "banned"}, http.StatusOK)
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
	Name        string `json:"name"`
	Host        string `json:"host"`
	Endpoint    string `json:"endpoint"`
	Port        int    `json:"port"`
	WGPort      int    `json:"wg_port"`
	PublicKey   string `json:"public_key"`
	CoreToken   string `json:"core_token"`
	Location    string `json:"location"`
	CountryCode string `json:"country_code"`
	MaxPeers    int    `json:"max_peers"`
	ProxyPort   int    `json:"proxy_port"`
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

func (h *Handler) AdminCreateServer(w http.ResponseWriter, r *http.Request) {
	var req CreateServerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.JsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Name == "" || req.Host == "" || req.PublicKey == "" || req.CoreToken == "" {
		respond.JsonError(w, "name, host, public_key and core_token are required", http.StatusBadRequest)
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
		CoreToken:   req.CoreToken,
		Location:    req.Location,
		CountryCode: req.CountryCode,
		MaxPeers:    req.MaxPeers,
		ProxyPort:   req.ProxyPort,
	}

	if err := h.serverRepo.Create(r.Context(), server); err != nil {
		slog.Error("admin create server error", "error", err)
		respond.JsonError(w, "failed to create server", http.StatusInternalServerError)
		return
	}
	server.ApplyCapabilities()

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.server.create",
		map[string]interface{}{"server_id": server.ID, "name": server.Name}, r.RemoteAddr)

	respond.JsonOK(w, server, http.StatusCreated)
}

type UpdateServerRequest struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Endpoint    string `json:"endpoint"`
	Port        int    `json:"port"`
	WGPort      int    `json:"wg_port"`
	PublicKey   string `json:"public_key"`
	CoreToken   string `json:"core_token"`
	Location    string `json:"location"`
	CountryCode string `json:"country_code"`
	MaxPeers    int    `json:"max_peers"`
	IsActive    *bool  `json:"is_active"`
	ProxyPort   *int   `json:"proxy_port"`
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
	if req.CoreToken != "" {
		server.CoreToken = req.CoreToken
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
	}
	if req.ProxyPort != nil {
		server.ProxyPort = *req.ProxyPort
	}

	if err := h.serverRepo.Update(r.Context(), server); err != nil {
		slog.Error("admin update server error", "server_id", server.ID, "error", err)
		respond.JsonError(w, "failed to update server", http.StatusInternalServerError)
		return
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

	if err := h.serverRepo.Delete(r.Context(), id); err != nil {
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

	server, err := h.serverRepo.GetByID(r.Context(), peer.ServerID)
	if err == nil {
		_ = CallCoreRemovePeer(server, peer.PublicKey)
		_ = h.serverRepo.UpdatePeerCount(r.Context(), peer.ServerID, -1)
	}

	h.detachPeerFromMeshSessions(r.Context(), peer)
	_ = h.peerRepo.Deactivate(r.Context(), peerID)

	admin := auth.GetUser(r)
	h.auditRepo.Log(r.Context(), &admin.ID, "admin.peer.disconnect",
		map[string]interface{}{"peer_id": peerID, "user_id": peer.UserID}, r.RemoteAddr)

	respond.JsonOK(w, map[string]string{"status": "disconnected"}, http.StatusOK)
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
