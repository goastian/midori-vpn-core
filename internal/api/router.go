package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/core"
	"github.com/goastian/midori-vpn-core/internal/respond"
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
		r.Post("/auth/callback", oauthH.Callback)
		r.Post("/auth/refresh", oauthH.Refresh)
		r.Get("/auth/config", oauthH.OIDCConfig)

		ch := control.NewHandler(pool, cfg)
		jwtMW := auth.JWTMiddleware(cfg, pool, jwks)

		// User-facing routes
		r.Route("/api/v1/control", func(r chi.Router) {
			r.Use(jwtMW)

			r.Get("/me", ch.Me)
			r.Post("/keypair", ch.GenerateKeypair)
			r.Get("/servers", ch.ListServers)
			r.Get("/servers/ping", ch.PingServers)

			// Connections
			r.Post("/connections", ch.Connect)
			r.Get("/connections", ch.ListMyConnections)
			r.Delete("/connections/{id}", ch.Disconnect)
			r.Get("/connections/{id}/config", ch.ExportConfig)
			r.Get("/connections/{id}/qr", ch.ExportQR)

			r.Get("/audit-logs", ch.MyAuditLogs)
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

			// Servers
			r.Get("/servers", ch.AdminListServers)
			r.Post("/servers", ch.AdminCreateServer)
			r.Put("/servers/{id}", ch.AdminUpdateServer)
			r.Delete("/servers/{id}", ch.AdminDeleteServer)

			// Peers
			r.Get("/peers", ch.AdminListPeers)
			r.Delete("/peers/{id}", ch.AdminForceDisconnectPeer)

			// Audit
			r.Get("/audit-logs", ch.AdminListAuditLogs)
		})

		// WebSocket for real-time stats (JWT protected via query param)
		wsHub := control.NewWSHub()
		go wsHub.Run()
		r.Get("/ws", func(w http.ResponseWriter, req *http.Request) {
			// Validate JWT from query param ?token=<jwt>
			tokenStr := req.URL.Query().Get("token")
			if tokenStr == "" {
				respond.JsonError(w, "missing token query parameter", http.StatusUnauthorized)
				return
			}
			if !auth.ValidateTokenOnly(cfg, jwks, tokenStr) {
				respond.JsonError(w, "invalid token", http.StatusUnauthorized)
				return
			}
			wsHub.HandleWS(w, req)
		})

		// Start background jobs with cancellation support
		jobCtx, jobCancel := context.WithCancel(context.Background())
		go control.StartStatsSync(jobCtx, pool, wsHub)
		go control.StartPeerCleanup(jobCtx, pool)
		SetJobCancel(jobCancel)
	}

	return r
}

// jobCancelFunc stores the cancel function for background jobs
var jobCancelFunc context.CancelFunc

func SetJobCancel(cancel context.CancelFunc) {
	jobCancelFunc = cancel
}

func CancelJobs() {
	if jobCancelFunc != nil {
		jobCancelFunc()
	}
}

func CORSMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	allowedOrigins := parseAllowedOrigins(cfg.CORSAllowedOrigins)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && isOriginAllowed(origin, allowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Core-Token")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Vary", "Origin")
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
	for _, pattern := range allowed {
		if pattern == origin {
			return true
		}
		// Support wildcard subdomain patterns like https://*.astian.org
		if strings.Contains(pattern, "*") {
			// Split pattern: "https://*.astian.org" -> scheme "https://" + "*.astian.org"
			if idx := strings.Index(pattern, "://"); idx != -1 {
				pScheme := pattern[:idx+3]
				pHost := pattern[idx+3:]
				oIdx := strings.Index(origin, "://")
				if oIdx == -1 {
					continue
				}
				oScheme := origin[:oIdx+3]
				oHost := origin[oIdx+3:]

				if pScheme != oScheme {
					continue
				}

				// "*.astian.org" matches "vpn.astian.org" and "sub.vpn.astian.org"
				if strings.HasPrefix(pHost, "*.") {
					suffix := pHost[1:] // ".astian.org"
					if strings.HasSuffix(oHost, suffix) {
						return true
					}
				}
			}
		}
	}
	return false
}
