package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/clientpki"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/core"
	"github.com/goastian/midori-vpn-core/internal/nodeauth"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/tunnel"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

func NewRouter(cfg *config.Config, mgr *wg.Manager, verifier *nodeauth.Verifier) *chi.Mux {
	return NewRouterWithDB(cfg, mgr, nil, nil, verifier, nil)
}

func NewRouterWithDB(cfg *config.Config, mgr *wg.Manager, pool *pgxpool.Pool, jwks *auth.JWKSProvider, verifier *nodeauth.Verifier, clientCertificateAuthority *clientpki.Authority) *chi.Mux {
	r := chi.NewRouter()
	var trustedExtRepo *repo.TrustedExtensionRepo
	var trustedExtensionOrigin ExtensionOriginChecker
	if pool != nil {
		trustedExtRepo = repo.NewTrustedExtensionRepo(pool)
		trustedExtensionOrigin = trustedExtRepo.Status
	}

	r.Use(sanitizedRequestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))
	r.Use(CORSMiddleware(cfg, trustedExtensionOrigin))
	if cfg.RateLimitRPS > 0 {
		r.Use(RateLimitMiddleware(cfg))
	}
	// Limit request body size to 1 MiB to prevent resource exhaustion attacks.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				RecordRequest(ww.Status())
			}()
			r.Body = http.MaxBytesReader(ww, r.Body, 1<<20)
			next.ServeHTTP(ww, r)
		})
	})

	h := core.NewHandler(cfg, mgr)
	healthChecker := NewHealthChecker(cfg, mgr, pool)
	metricsExporter := NewMetricsExporter(mgr)

	// Public Health Probes & Telemetry
	r.Get("/health", h.Health)
	r.Get("/livez", healthChecker.Livez)
	r.Get("/readyz", healthChecker.Readyz)
	r.Get("/metrics", metricsExporter.Handler)
	if cfg.WSSTunnelEnabled {
		serverID, _ := uuid.Parse(cfg.WSSTunnelServerID)
		gateway := tunnel.NewWSGateway(cfg.WGPort, cfg.CredentialSigningSecret, serverID, cfg.WSSTunnelMaxClients)
		r.Get("/api/v1/tunnel/ws", gateway.Handler)
	}

	// WireGuard core API protected by signed Ed25519 node requests.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(core.AuthMiddleware(verifier))

		// Peers (core)
		r.Post("/peers", h.AddPeer)
		r.Delete("/peers/{pubkey}", h.RemovePeer)
		r.Put("/peers/{pubkey}", h.UpdatePeer)
		r.Get("/peers/{pubkey}/stats", h.PeerStats)
		r.Get("/peers", h.ListPeers)

		// Stats
		r.Get("/stats", h.ServerStats)
	})

	// Control API (JWT/Authentik protected) — only if DB is available
	if pool != nil && jwks != nil {
		oauthH := control.NewOAuthHandler(cfg, trustedExtRepo)
		r.Get(cfg.ExtensionCallbackPath, oauthH.ExtensionCallback)
		r.Post("/api/v1/auth/callback", oauthH.Callback)
		// Per-refresh_token throttling: protects against credential brute-force
		// and replay even when the global IP limiter is bypassed by IP rotation.
		r.With(RefreshRateLimitMiddleware()).Post("/api/v1/auth/refresh", oauthH.Refresh)
		r.Post("/api/v1/auth/logout", oauthH.Logout)
		r.Get("/api/v1/auth/config", oauthH.OIDCConfig)

		jwtMW := auth.JWTMiddleware(cfg, pool, jwks)

		// Create WS hub early so mesh handler can broadcast to connected clients.
		wsHub := control.NewWSHub(cfg)
		go wsHub.Run()
		ch := control.NewHandlerWithMesh(pool, cfg, mgr, wsHub)
		ch.SetNodeVerifier(verifier)
		ch.SetClientCertificateAuthority(clientCertificateAuthority)
		if clientCertificateAuthority != nil {
			r.Get("/pki/client-ca.pem", ch.ClientCACertificate)
			r.Get("/pki/client.crl", ch.ClientCertificateCRL)
		}

		// User-facing routes
		r.Route("/api/v1/control", func(r chi.Router) {
			r.Use(jwtMW)
			r.Use(control.BannedCheck)

			r.Get("/me", ch.Me)
			r.Get("/quota", ch.GetQuota)
			r.Post("/proxy-credentials", ch.ProxyCredentials)
			r.Post("/tunnel-credentials", ch.TunnelCredentials)
			r.Get("/servers", ch.ListServers)
			r.Get("/servers/ping", ch.PingServers)
			r.Get("/servers/{id}/ikev2.mobileconfig", ch.ExportIKEv2MobileConfig)
			r.Post("/certificates", ch.EnrollDeviceCertificate)
			r.Get("/certificates", ch.ListDeviceCertificates)
			r.Delete("/certificates/{id}", ch.RevokeDeviceCertificate)

			// Connections
			r.Post("/connections", ch.Connect)
			r.Get("/connections", ch.ListMyConnections)
			r.Delete("/connections/{id}", ch.Disconnect)
			r.Delete("/connections/{id}/device", ch.DeleteConnection)
			r.Get("/connections/{id}/config", ch.ExportConfig)
			r.Get("/connections/{id}/qr", ch.ExportQR)

			r.Get("/audit-logs", ch.MyAuditLogs)

			// Mesh networking
			mh := control.NewMeshHandler(pool, mgr, wsHub, cfg.TrustedProxies)
			exitH := control.NewExitNodeHandler(pool)
			r.Route("/mesh", func(r chi.Router) {
				r.Post("/", mh.CreateMesh)
				r.Get("/", mh.ListMyMeshes)
				r.Post("/join", mh.JoinMesh)
				// Session mesh (auto-create on login, auto-delete on close)
				r.Post("/auto", mh.AutoMesh)
				r.Delete("/auto", mh.DeleteAutoMesh)
				// Node activation (simple toggle — must be before /{id})
				r.Get("/node", mh.NodeStatus)
				r.Post("/node", mh.ActivateNode)
				r.Delete("/node", mh.DeactivateNode)
				// Exit node management
				r.Get("/exit-nodes", exitH.ListExitNodes)
				r.Post("/exit-node/register", exitH.RegisterExitNode)
				r.Delete("/exit-node/register", exitH.DeregisterExitNode)
				r.Put("/exit-node", exitH.SetExitNode)
				r.Delete("/exit-node", exitH.ClearExitNode)
				r.Get("/{id}", mh.GetMesh)
				r.Delete("/{id}", mh.LeaveMesh)
				r.Post("/{id}/invite", mh.RegenerateInvite)
			})
		})

		// Admin routes
		r.Route("/api/v1/admin", func(r chi.Router) {
			r.Use(jwtMW)
			r.Use(control.AdminOnly)

			// Dashboard
			r.Get("/dashboard/stats", ch.AdminDashboardStats)
			r.Get("/health", healthChecker.DetailedReadyz)

			// Users
			r.Get("/users", ch.AdminListUsers)
			r.Post("/users", ch.AdminCreateUser)
			r.Get("/users/{id}", ch.AdminGetUser)
			r.Put("/users/{id}", ch.AdminUpdateUser)
			r.Delete("/users/{id}", ch.AdminDeleteUser)
			r.Post("/users/{id}/ban", ch.AdminBanUser)
			r.Delete("/users/{id}/ban", ch.AdminUnbanUser)

			// Servers
			r.Get("/servers", ch.AdminListServers)
			r.Get("/servers/ping", ch.AdminPingServers)
			r.Post("/servers", ch.AdminCreateServer)
			r.Put("/servers/{id}", ch.AdminUpdateServer)
			r.Delete("/servers/{id}", ch.AdminDeleteServer)

			// Signed node identities
			r.Get("/node-identities", ch.AdminListNodeIdentities)
			r.Post("/node-identities", ch.AdminRegisterNodeIdentity)
			r.Delete("/node-identities/{nodeID}", ch.AdminRevokeNodeIdentity)
			r.Post("/node-identities/{nodeID}/restore", ch.AdminRestoreNodeIdentity)

			// Peers
			r.Get("/peers", ch.AdminListPeers)
			r.Delete("/peers/{id}", ch.AdminForceDisconnectPeer)

			// Mesh overview (read-only for admins)
			adminMeshH := control.NewAdminMeshHandler(pool)
			r.Get("/mesh", adminMeshH.AdminListMeshes)

			// Audit
			r.Get("/audit-logs", ch.AdminListAuditLogs)
			r.Get("/trusted-extension-origins", ch.AdminListTrustedExtensionOrigins)
			r.Put("/trusted-extension-origins/{id}", ch.AdminUpdateTrustedExtensionOrigin)
		})

		// WebSocket for real-time stats (JWT authenticated via first message)
		r.Get("/ws", func(w http.ResponseWriter, req *http.Request) {
			wsHub.HandleWS(w, req, cfg, jwks)
		})

		// Start background jobs with cancellation support
		jobCtx, jobCancel := context.WithCancel(context.Background())
		go control.StartStatsSync(jobCtx, pool, wsHub)
		go control.StartTransportHealthSync(jobCtx, pool)
		go control.StartPeerCleanup(jobCtx, pool)
		go control.StartSessionMeshCleanup(jobCtx, pool)
		SetJobCancel(jobCancel)
	}

	return r
}

// sanitizedRequestLogger records enough request metadata for operations while
// deliberately excluding the query string, client address, headers and body.
// OAuth callbacks carry short-lived authorization codes and CSRF state in the
// query, so logging RequestURI would turn normal access logs into credentials.
func sanitizedRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

// jobCancelFunc stores the cancel function for background jobs
var (
	jobCancelMu   sync.Mutex
	jobCancelFunc context.CancelFunc
)

func SetJobCancel(cancel context.CancelFunc) {
	jobCancelMu.Lock()
	defer jobCancelMu.Unlock()

	if jobCancelFunc != nil {
		jobCancelFunc()
	}
	jobCancelFunc = cancel
}

func CancelJobs() {
	jobCancelMu.Lock()
	cancel := jobCancelFunc
	jobCancelFunc = nil
	jobCancelMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

type ExtensionOriginChecker func(context.Context, string) (repo.ExtensionOriginStatus, error)

func CORSMiddleware(cfg *config.Config, extensionCheckers ...ExtensionOriginChecker) func(http.Handler) http.Handler {
	allowedOrigins := parseAllowedOrigins(cfg.CORSAllowedOrigins)
	allowedExtensionOrigins := parseAllowedOrigins(cfg.AllowedExtensionOrigins)
	var trustedExtensionOrigin ExtensionOriginChecker
	if len(extensionCheckers) > 0 {
		trustedExtensionOrigin = extensionCheckers[0]
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			// Always set Vary: Origin so caches distinguish responses by origin
			w.Header().Set("Vary", "Origin")

			originAllowed := origin != "" && isOriginAllowed(origin, allowedOrigins)
			if isBrowserExtensionOrigin(origin) {
				originAllowed = extensionOriginAllowed(r, origin, allowedExtensionOrigins, trustedExtensionOrigin)
			}

			if originAllowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			}

			if r.Method == "OPTIONS" {
				w.WriteHeader(204)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func extensionOriginAllowed(r *http.Request, origin string, configured []string, trusted ExtensionOriginChecker) bool {
	for _, allowed := range configured {
		if origin == allowed {
			return true
		}
	}
	if trusted == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	status, err := trusted(ctx, origin)
	if err != nil {
		slog.Error("CORS trusted extension origin lookup failed", "error", err)
		return false
	}
	if status == repo.ExtensionOriginTrusted {
		return true
	}
	// Only an origin that has never been seen may bootstrap through the exact
	// PKCE exchange route. Revocation is authoritative and blocks new OAuth.
	return status == repo.ExtensionOriginUnknown &&
		r.URL.Path == "/api/v1/auth/callback" &&
		(r.Method == http.MethodPost || r.Method == http.MethodOptions)
}

func isBrowserExtensionOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "moz-extension" && parsed.Scheme != "chrome-extension") {
		return false
	}
	return parsed.Host != "" && parsed.User == nil && parsed.Port() == "" && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func parseAllowedOrigins(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func isOriginAllowed(origin string, allowed []string) bool {
	// Parse the incoming origin once for proper scheme/host extraction.
	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin.Host == "" || parsedOrigin.Scheme == "" {
		return false
	}
	originScheme := parsedOrigin.Scheme
	originHost := parsedOrigin.Hostname() // strips port, decodes percent-encoding

	for _, pattern := range allowed {
		if pattern == origin {
			return true
		}
		// Support wildcard subdomain patterns like https://*.astian.org
		if !strings.Contains(pattern, "*") {
			continue
		}
		// Replace wildcard with a placeholder so url.Parse works correctly.
		parsedPattern, pErr := url.Parse(strings.Replace(pattern, "*", "_wc_", 1))
		if pErr != nil || parsedPattern.Host == "" || parsedPattern.Scheme == "" {
			continue
		}
		if originScheme != parsedPattern.Scheme {
			continue
		}
		// patternHost is like "_wc_.astian.org"; base is ".astian.org"
		patternHost := parsedPattern.Hostname()
		baseDomain := strings.TrimPrefix(patternHost, "_wc_")
		// baseDomain must start with "." (e.g. ".astian.org") and originHost
		// must end with exactly that suffix AND have a non-empty label before it.
		if strings.HasPrefix(baseDomain, ".") &&
			strings.HasSuffix(originHost, baseDomain) &&
			len(originHost) > len(baseDomain) {
			return true
		}
	}
	return false
}
