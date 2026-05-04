package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/core"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

func NewRouter(cfg *config.Config, mgr *wg.Manager) *chi.Mux {
	return NewRouterWithDB(cfg, mgr, nil, nil)
}

func NewRouterWithDB(cfg *config.Config, mgr *wg.Manager, pool *pgxpool.Pool, jwks *auth.JWKSProvider) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))
	r.Use(CORSMiddleware(cfg))
	if cfg.RateLimitRPS > 0 {
		r.Use(RateLimitMiddleware(cfg))
	}
	// Limit request body size to 1 MiB to prevent resource exhaustion attacks.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			next.ServeHTTP(w, r)
		})
	})

	h := core.NewHandler(cfg, mgr)

	// Public
	r.Get("/health", h.Health)

	// WireGuard core API (X-Core-Token protected)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(core.AuthMiddleware(cfg.AuthToken))

		// Peers (core)
		r.Post("/peers", h.AddPeer)
		r.Delete("/peers/{pubkey}", h.RemovePeer)
		r.Put("/peers/{pubkey}", h.UpdatePeer)
		r.Get("/peers/{pubkey}/stats", h.PeerStats)
		r.Get("/peers", h.ListPeers)

		// Keypair
		r.Post("/keypair", h.GenerateKeypair)

		// Stats
		r.Get("/stats", h.ServerStats)
	})

	// Control API (JWT/Authentik protected) — only if DB is available
	if pool != nil && jwks != nil {
		oauthH := control.NewOAuthHandler(cfg)
		r.Post("/api/v1/auth/callback", oauthH.Callback)
		r.Post("/api/v1/auth/refresh", oauthH.Refresh)
		r.Post("/api/v1/auth/logout", oauthH.Logout)
		r.Get("/api/v1/auth/config", oauthH.OIDCConfig)

		jwtMW := auth.JWTMiddleware(cfg, pool, jwks)

		// Create WS hub early so mesh handler can broadcast to connected clients.
		wsHub := control.NewWSHub(cfg)
		go wsHub.Run()
		ch := control.NewHandlerWithMesh(pool, cfg, mgr, wsHub)

		// User-facing routes
		r.Route("/api/v1/control", func(r chi.Router) {
			r.Use(jwtMW)
			r.Use(control.BannedCheck)

			r.Get("/me", ch.Me)
			r.Post("/keypair", ch.GenerateKeypair)
			r.Get("/servers", ch.ListServers)
			r.Get("/servers/ping", ch.PingServers)

			// Connections
			r.Post("/connections", ch.Connect)
			r.Get("/connections", ch.ListMyConnections)
			r.Delete("/connections/{id}", ch.Disconnect)
			r.Delete("/connections/{id}/device", ch.DeleteConnection)
			r.Get("/connections/{id}/config", ch.ExportConfig)
			r.Get("/connections/{id}/qr", ch.ExportQR)

			r.Get("/audit-logs", ch.MyAuditLogs)

			// Mesh networking
			mh := control.NewMeshHandler(pool, mgr, wsHub)
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

			// Peers
			r.Get("/peers", ch.AdminListPeers)
			r.Delete("/peers/{id}", ch.AdminForceDisconnectPeer)

			// Mesh overview (read-only for admins)
			adminMeshH := control.NewAdminMeshHandler(pool)
			r.Get("/mesh", adminMeshH.AdminListMeshes)

			// Audit
			r.Get("/audit-logs", ch.AdminListAuditLogs)
		})

		// WebSocket for real-time stats (JWT authenticated via first message)
		r.Get("/ws", func(w http.ResponseWriter, req *http.Request) {
			wsHub.HandleWS(w, req, cfg, jwks)
		})

		// Start background jobs with cancellation support
		jobCtx, jobCancel := context.WithCancel(context.Background())
		go control.StartStatsSync(jobCtx, pool, wsHub)
		go control.StartPeerCleanup(jobCtx, pool)
		go control.StartSessionMeshCleanup(jobCtx, pool)
		SetJobCancel(jobCancel)
	}

	return r
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

func CORSMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	allowedOrigins := parseAllowedOrigins(cfg.CORSAllowedOrigins)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			// Always set Vary: Origin so caches distinguish responses by origin
			w.Header().Set("Vary", "Origin")

			if origin != "" && isOriginAllowed(origin, allowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Core-Token")
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
	// Browser extensions are trusted clients with dynamic origins.
	if strings.HasPrefix(origin, "moz-extension://") ||
		strings.HasPrefix(origin, "chrome-extension://") {
		return true
	}

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
