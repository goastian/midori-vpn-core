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
	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/nodeauth"
	"github.com/goastian/midori-vpn-core/internal/proxytoken"
	"github.com/goastian/midori-vpn-core/internal/repo"
	"github.com/goastian/midori-vpn-core/internal/tunnel"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

func NewRouter(cfg *config.Config, mgr *wg.Manager, verifier *nodeauth.Verifier, transportVerifier *proxytoken.Verifier) *chi.Mux {
	return NewRouterWithDB(cfg, mgr, nil, nil, verifier, nil, transportVerifier)
}

func NewRouterWithDB(cfg *config.Config, mgr *wg.Manager, pool *pgxpool.Pool, jwks *auth.JWKSProvider, verifier *nodeauth.Verifier, clientCertificateAuthority *clientpki.Authority, transportVerifier *proxytoken.Verifier, dataCipher ...*dataencryption.Cipher) *chi.Mux {
	return newRouter(cfg, mgr, pool, jwks, verifier, clientCertificateAuthority, transportVerifier, resolveDataCipher(cfg, dataCipher), true)
}

// newRouter keeps route registration independently testable without starting
// long-lived workers. Production constructors always enable the workers.
func newRouter(cfg *config.Config, mgr *wg.Manager, pool *pgxpool.Pool, jwks *auth.JWKSProvider, verifier *nodeauth.Verifier, clientCertificateAuthority *clientpki.Authority, transportVerifier *proxytoken.Verifier, dataCipher *dataencryption.Cipher, startWorkers bool) *chi.Mux {
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
			started := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				RecordRequest(ww.Status(), time.Since(started), r.Method, r.URL.Path)
			}()
			r.Body = http.MaxBytesReader(ww, r.Body, 1<<20)
			next.ServeHTTP(ww, r)
		})
	})

	h := core.NewHandler(cfg, mgr)
	healthChecker := NewHealthChecker(cfg, mgr, pool)

	// Public Health Probes & Telemetry
	r.Get("/health", h.Health)
	r.Get("/livez", healthChecker.Livez)
	r.Get("/readyz", healthChecker.Readyz)
	edgeHealthRateLimit := EdgeHealthRateLimitMiddleware(cfg.TrustedProxies)
	r.With(edgeHealthRateLimit).Get("/.well-known/midorivpn/edge-health", h.EdgeHealth)
	r.With(edgeHealthRateLimit).Head("/.well-known/midorivpn/edge-health", h.EdgeHealth)
	if cfg.WSSTunnelEnabled {
		serverID, _ := uuid.Parse(cfg.WSSTunnelServerID)
		clusterID, _ := uuid.Parse(cfg.TransportClusterID)
		gateway := tunnel.NewWSGateway(cfg.WGPort, transportVerifier, serverID, clusterID, cfg.WSSTunnelMaxClients)
		r.Get("/api/v1/tunnel/ws", gateway.Handler)
	}
	if pool != nil {
		nodePlaneHandler := control.NewNodePlaneHandler(pool, cfg)
		r.Post("/api/v1/node/enroll", nodePlaneHandler.Enroll)
		r.Post("/api/v1/node/heartbeat", nodePlaneHandler.Heartbeat)
		r.Get("/api/v1/node/desired-state", nodePlaneHandler.DesiredState)
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
		if startWorkers {
			go wsHub.Run()
		}
		ch := control.NewHandlerWithMeshAndDataEncryption(pool, cfg, mgr, wsHub, dataCipher)
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
			r.Get("/dashboard/summary", ch.DashboardSummary)
			r.Post("/proxy-credentials", ch.ProxyCredentials)
			r.Post("/tunnel-credentials", ch.TunnelCredentials)
			r.Get("/servers", ch.ListServers)
			r.Get("/servers/candidates", ch.ListServerCandidates)
			r.Post("/certificates", ch.EnrollDeviceCertificate)
			r.Get("/certificates", ch.ListDeviceCertificates)
			r.Delete("/certificates/{id}", ch.RevokeDeviceCertificate)
			r.Get("/devices", ch.ListMyDevices)
			r.Patch("/devices/{id}", ch.UpdateMyDevice)
			r.Delete("/devices/{id}", ch.DeleteMyDevice)
			r.Get("/devices/{id}/sessions", ch.ListMyDeviceSessions)

			// Connections
			r.Post("/connections", ch.Connect)
			r.Get("/connections", ch.ListMyConnections)
			r.Delete("/connections/{id}", ch.Disconnect)
			r.Get("/connections/{id}/config", ch.ExportConfig)
			r.Get("/connections/{id}/qr", ch.ExportQR)

			r.Get("/audit-logs", ch.MyAuditLogs)

			// Mesh networking
			mh := control.NewMeshHandler(pool, mgr, wsHub, cfg.TrustedProxies)
			exitH := control.NewExitNodeHandler(pool)
			r.Post("/mesh", mh.CreateMesh)
			r.Get("/mesh", mh.ListMyMeshes)
			r.Post("/mesh/join", mh.JoinMesh)
			// Session mesh (auto-create on login, auto-delete on close)
			r.Post("/mesh/auto", mh.AutoMesh)
			r.Delete("/mesh/auto", mh.DeleteAutoMesh)
			// Node activation (simple toggle — must be before /mesh/{id})
			r.Get("/mesh/node", mh.NodeStatus)
			r.Post("/mesh/node", mh.ActivateNode)
			r.Delete("/mesh/node", mh.DeactivateNode)
			// Exit node management
			r.Get("/mesh/exit-nodes", exitH.ListExitNodes)
			r.Post("/mesh/exit-node/register", exitH.RegisterExitNode)
			r.Delete("/mesh/exit-node/register/{meshID}", exitH.DeregisterExitNode)
			r.Put("/mesh/exit-node", exitH.SetExitNode)
			r.Delete("/mesh/exit-node", exitH.ClearExitNode)
			r.Get("/mesh/{id}", mh.GetMesh)
			r.Delete("/mesh/{id}", mh.LeaveMesh)
			r.Post("/mesh/{id}/invite", mh.RegenerateInvite)
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
			r.Get("/servers/reachability", ch.AdminServerReachability)
			r.Post("/servers", ch.AdminCreateServer)
			r.Put("/servers/{id}", ch.AdminUpdateServer)
			r.Delete("/servers/{id}", ch.AdminDeleteServer)

			// Signed node identities
			r.Get("/node-identities", ch.AdminListNodeIdentities)
			r.Post("/node-identities", ch.AdminRegisterNodeIdentity)
			r.Delete("/node-identities/{nodeID}", ch.AdminRevokeNodeIdentity)
			r.Post("/node-identities/{nodeID}/restore", ch.AdminRestoreNodeIdentity)

			// Cluster and enrolled Core node lifecycle
			r.Get("/clusters", ch.AdminListClusters)
			r.Post("/clusters", ch.AdminCreateCluster)
			r.Get("/clusters/{clusterID}/nodes", ch.AdminListCoreNodes)
			r.Post("/clusters/{clusterID}/nodes", ch.AdminCreateCoreNode)
			r.Patch("/nodes/{nodeID}", ch.AdminUpdateCoreNode)
			r.Post("/nodes/{nodeID}/enrollment-token", ch.AdminIssueNodeEnrollmentToken)
			r.Post("/nodes/{nodeID}/revoke", ch.AdminRevokeCoreNode)
			r.Post("/nodes/{nodeID}/desired-state", ch.AdminCreateDesiredState)

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

		if startWorkers {
			// Start background jobs with cancellation support.
			jobCtx, jobCancel := context.WithCancel(context.Background())
			go control.StartStatsSync(jobCtx, pool, wsHub, dataCipher)
			go control.StartTransportHealthSync(jobCtx, pool)
			go control.StartPeerCleanup(jobCtx, pool)
			go control.StartSessionMeshCleanup(jobCtx, pool)
			if cfg.ControlNodeID != "" && cfg.ControlNodePrivateKey != "" {
				go control.StartDesiredStateRenewal(jobCtx, pool, cfg)
			}
			SetJobCancel(jobCancel)
		}
	}

	return r
}

func resolveDataCipher(cfg *config.Config, ciphers []*dataencryption.Cipher) *dataencryption.Cipher {
	if len(ciphers) > 0 {
		return ciphers[0]
	}
	if cfg != nil && len(cfg.ControlDataEncryptionKey) > 0 {
		dataCipher, _ := dataencryption.New(cfg.ControlDataEncryptionKey)
		return dataCipher
	}
	return nil
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
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
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
