package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/goastian/astian-vpn-core/internal/config"
	"github.com/goastian/astian-vpn-core/internal/wg"
)

func NewRouter(cfg *config.Config, mgr *wg.Manager) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	h := NewHandler(cfg, mgr)

	// Public
	r.Get("/health", h.Health)

	// Protected routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(AuthMiddleware(cfg.AuthToken))

		// Peers
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

	return r
}
