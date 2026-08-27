package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/goastian/midori-vpn-core/internal/ikev2health"
)

func main() {
	healthSocket := envOrDefault("IKEV2_HEALTH_SOCKET", "/run/midorivpn-health/ikev2.sock")
	if healthSocket != "/run/midorivpn-health/ikev2.sock" {
		log.Fatal("IKEV2_HEALTH_SOCKET must use the fixed private runtime path")
	}
	checker := ikev2health.Checker{
		SwanctlPath: envOrDefault("SWANCTL_PATH", "/usr/sbin/swanctl"),
		VICISocket:  requiredEnv("IKEV2_VICI_SOCKET"),
		Connection:  requiredEnv("IKEV2_CONNECTION_NAME"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := checker.Healthy(ctx); err != nil {
			log.Printf("IKEv2 health check failed: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ikev2": true})
	})
	if err := os.Remove(healthSocket); err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}
	listener, err := net.Listen("unix", healthSocket)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	defer os.Remove(healthSocket)
	if err := os.Chmod(healthSocket, 0o666); err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
	}
	log.Printf("IKEv2 health server listening on %s", healthSocket)
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func requiredEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("missing required environment variable: %s", name)
	}
	return value
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
