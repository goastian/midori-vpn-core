package control

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/billing"
	"github.com/goastian/midori-vpn-core/internal/clientpki"
	"github.com/goastian/midori-vpn-core/internal/config"
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

const edgeHealthPath = "/.well-known/midorivpn/edge-health"

// normalizeProbeURL validates the public endpoint clients may measure before
// selecting a Core. It is intentionally HTTPS-only and carries no credentials,
// query, fragment, or arbitrary path.
func normalizeProbeURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("probe_url is required")
	}
	parsed, err := url.ParseRequestURI(trimmed)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" {
		return "", errors.New("probe_url must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("probe_url must not contain credentials, query, or fragment")
	}
	if parsed.Path != edgeHealthPath || parsed.RawPath != "" {
		return "", fmt.Errorf("probe_url path must be %s", edgeHealthPath)
	}
	if parsed.Hostname() == "" {
		return "", errors.New("probe_url must contain a hostname")
	}
	return parsed.String(), nil
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
	userRepo              *repo.UserRepo
	serverRepo            *repo.ServerRepo
	peerRepo              *repo.PeerRepo
	peerOperationRepo     *repo.PeerOperationRepo
	deviceRepo            *repo.DeviceRepo
	dashboardRepo         *repo.DashboardRepo
	meshRepo              *repo.MeshRepo
	auditRepo             *repo.AuditRepo
	trustedExtensionRepo  *repo.TrustedExtensionRepo
	billingClient         *billing.Client
	wgMgr                 *wg.Manager
	hub                   *WSHub
	maxDevicesPerUser     int
	appEnv                string
	coreAllowLoopback     bool
	publicBaseURL         string
	vpnDNS                string
	transportTokenSigner  *proxytoken.Signer
	connectLimiter        *userRateLimiter // per-user rate limit for the /connect endpoint
	nodeVerifier          *nodeauth.Verifier
	clientCertificateRepo *repo.DeviceCertificateRepo
	clientCertificateCA   *clientpki.Authority
	multiclusterRepo      *repo.MulticlusterRepo
	desiredStateSigner    *desiredstate.Signer
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
		userRepo:              repo.NewUserRepo(pool),
		serverRepo:            repo.NewServerRepo(pool),
		peerRepo:              repo.NewPeerRepo(pool, dataCipher),
		peerOperationRepo:     repo.NewPeerOperationRepo(pool, dataCipher),
		deviceRepo:            repo.NewDeviceRepo(pool),
		dashboardRepo:         repo.NewDashboardRepo(pool),
		meshRepo:              repo.NewMeshRepo(pool),
		auditRepo:             repo.NewAuditRepo(pool),
		trustedExtensionRepo:  repo.NewTrustedExtensionRepo(pool),
		clientCertificateRepo: repo.NewDeviceCertificateRepo(pool),
		multiclusterRepo:      repo.NewMulticlusterRepo(pool),
		billingClient:         billing.NewClient(cfg, billingRedis),
		wgMgr:                 wgMgr,
		hub:                   hub,
		maxDevicesPerUser:     cfg.MaxDevicesPerUser,
		appEnv:                cfg.AppEnv,
		coreAllowLoopback:     cfg.CoreAllowHTTP,
		publicBaseURL:         cfg.PublicBaseURL,
		vpnDNS:                cfg.VpnDNS,
	}
	if cfg.ControlNodeID != "" && cfg.ControlNodePrivateKey != "" && cfg.TransportTokenIssuer != "" {
		h.transportTokenSigner, _ = proxytoken.NewSigner(cfg.ControlNodeID, cfg.TransportTokenIssuer, cfg.ControlNodePrivateKey)
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
