package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/goastian/midori-vpn-core/internal/api"
	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/db"
	"github.com/goastian/midori-vpn-core/internal/proxy"
	"github.com/goastian/midori-vpn-core/internal/respond"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

func main() {
	cfg := config.Load()
	respond.SetAppEnv(cfg.AppEnv)

	// Initialize core HTTP client with TLS settings
	control.InitCoreClient(cfg.CoreTLSSkipVerify, cfg.CoreAllowHTTP, cfg.CoreAllowedHosts)

	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

		slog.Info("Control API enabled", "auth", "PostgreSQL + Authentik")
		router = api.NewRouterWithDB(cfg, manager, pool, jwks)

		// Start HTTP CONNECT proxy if enabled
		if cfg.ProxyEnabled {
			proxySrv := proxy.NewWithDB(cfg, jwks, pool)
			go func() {
				if err := proxySrv.Start(shutdownCtx); err != nil {
					slog.Error("proxy server stopped", "error", err)
				}
			}()
		}
	} else {
		slog.Info("Control API disabled", "reason", "no DATABASE_URL or AUTHENTIK_CLIENT_ID")
		router = api.NewRouter(cfg, manager)
	}

	addr := fmt.Sprintf(":%s", cfg.Port)
	slog.Info("MidoriVPN listening", "addr", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	select {
	case err := <-serverErrCh:
		if err != nil {
			api.CancelJobs()
			log.Fatalf("server error: %v", err)
		}
	case <-shutdownCtx.Done():
		slog.Info("shutting down...")

		// Stop periodic jobs before shutting down the HTTP server.
		api.CancelJobs()

		// Give in-flight requests up to 15s to complete.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown error", "error", err)
		}

		if err := <-serverErrCh; err != nil {
			slog.Error("server stopped with error", "error", err)
		}
	}

	slog.Info("server stopped")
}
