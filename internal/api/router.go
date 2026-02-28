package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
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
	r.Use(CORSMiddleware)

	h := NewHandler(cfg, mgr)

	// Public
	r.Get("/health", h.Health)

	// WireGuard core API (X-Core-Token protected)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(AuthMiddleware(cfg.AuthToken))

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
		oauthH := NewOAuthHandler(cfg)
		r.Post("/auth/callback", oauthH.Callback)
		r.Get("/auth/config", oauthH.OIDCConfig)

		ch := NewControlHandler(pool)

		r.Route("/api/v1/control", func(r chi.Router) {
			r.Use(auth.JWTMiddleware(cfg, pool, jwks))

			r.Get("/me", ch.Me)

			r.Get("/servers", ch.ListServers)
			r.Post("/servers", ch.CreateServer)
			r.Delete("/servers/{id}", ch.DeleteServer)

			r.Get("/peers", ch.ListMyPeers)
			r.Post("/peers", ch.ConnectPeer)
			r.Delete("/peers/{id}", ch.DisconnectPeer)

			r.Get("/audit", ch.MyAuditLogs)
		})
	}

	return r
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Core-Token")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}

		next.ServeHTTP(w, r)
	})
}
