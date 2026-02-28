package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/goastian/midori-vpn-core/internal/api"
	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/db"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

func main() {
	cfg := config.Load()

	manager, err := wg.NewManager(cfg)
	if err != nil {
		log.Fatalf("failed to initialize WireGuard manager: %v", err)
	}
	defer manager.Close()

	// Optional: connect to PostgreSQL + JWKS if DATABASE_URL is set
	var router http.Handler
	if cfg.DatabaseURL != "" && cfg.AuthentikClientID != "" {
		pool, err := db.Connect(cfg)
		if err != nil {
			log.Fatalf("failed to connect to database: %v", err)
		}
		defer pool.Close()

		if err := db.RunMigrations(cfg.DatabaseURL); err != nil {
			log.Fatalf("failed to run migrations: %v", err)
		}

		jwks, err := auth.NewJWKSProvider(cfg)
		if err != nil {
			log.Fatalf("failed to initialize JWKS provider: %v", err)
		}

		log.Println("Control API enabled (PostgreSQL + Authentik)")
		router = api.NewRouterWithDB(cfg, manager, pool, jwks)
	} else {
		log.Println("Control API disabled (no DATABASE_URL or AUTHENTIK_CLIENT_ID)")
		router = api.NewRouter(cfg, manager)
	}

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("MidoriVPN listening on %s", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
