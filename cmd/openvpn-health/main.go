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

	"github.com/goastian/midori-vpn-core/internal/openvpnhealth"
)

func main() {
	listenAddress := envOrDefault("OPENVPN_HEALTH_LISTEN", "127.0.0.1:9194")
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("OPENVPN_HEALTH_LISTEN must be a loopback IP and port")
	}
	checker := openvpnhealth.Checker{
		ManagementSocket: requiredEnv("OPENVPN_MANAGEMENT_SOCKET"),
		LogPath:          requiredEnv("OPENVPN_LOG_PATH"),
		InterfaceName:    requiredEnv("OPENVPN_INTERFACE"),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := checker.Healthy(ctx); err != nil {
			log.Printf("OpenVPN health check failed: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "dco": true})
	})
	server := &http.Server{
		Addr: listenAddress, Handler: mux,
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
	}
	log.Printf("OpenVPN health server listening on %s", listenAddress)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
