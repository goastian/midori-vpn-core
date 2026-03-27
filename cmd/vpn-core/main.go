package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goastian/midori-vpn-core/internal/api"
	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/db"
	"github.com/goastian/midori-vpn-core/internal/respond"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

func main() {
	cfg := config.Load()
	respond.SetAppEnv(cfg.AppEnv)

	// Initialize core HTTP client with TLS settings
	control.InitCoreClient(cfg.CoreTLSSkipVerify, cfg.CoreAllowHTTP)

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

		// Cancel background jobs first
		api.CancelJobs()

		// Give in-flight requests up to 15s to complete
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
		}
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("server stopped")
}
