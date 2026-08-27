package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/goastian/midori-vpn-core/internal/ikev2health"
)

func main() {
	healthFile := envOrDefault("IKEV2_HEALTH_FILE", ikev2health.StatusFile)
	if healthFile != ikev2health.StatusFile {
		log.Fatal("IKEV2_HEALTH_FILE must use the fixed private runtime path")
	}
	checker := ikev2health.Checker{
		SwanctlPath: envOrDefault("SWANCTL_PATH", "/usr/sbin/swanctl"),
		VICISocket:  requiredEnv("IKEV2_VICI_SOCKET"),
		Connection:  requiredEnv("IKEV2_CONNECTION_NAME"),
	}
	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer os.Remove(healthFile)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		checkCtx, cancel := context.WithTimeout(runCtx, 3*time.Second)
		err := checker.Healthy(checkCtx)
		cancel()
		if err != nil {
			_ = os.Remove(healthFile)
			log.Printf("IKEv2 health check failed: %v", err)
		} else if err := ikev2health.Publish(healthFile, time.Now().UTC()); err != nil {
			log.Fatalf("publish IKEv2 health: %v", err)
		}
		select {
		case <-runCtx.Done():
			return
		case <-ticker.C:
		}
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
