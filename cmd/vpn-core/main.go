package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/goastian/midori-vpn-core/internal/api"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

func main() {
	cfg := config.Load()

	manager, err := wg.NewManager(cfg)
	if err != nil {
		log.Fatalf("failed to initialize WireGuard manager: %v", err)
	}
	defer manager.Close()

	router := api.NewRouter(cfg, manager)

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
