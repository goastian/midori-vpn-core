package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/goastian/midori-vpn-core/internal/openvpnhealth"
)

func main() {
	checker := openvpnhealth.Checker{
		ManagementSocket: requiredEnv("OPENVPN_MANAGEMENT_SOCKET"),
		LogPath:          requiredEnv("OPENVPN_LOG_PATH"),
		InterfaceName:    requiredEnv("OPENVPN_INTERFACE"),
	}
	healthFile := requiredEnv("OPENVPN_HEALTH_FILE")
	runFilePublisher(checker, healthFile)
}

func runFilePublisher(checker openvpnhealth.Checker, healthFile string) {
	if healthFile != openvpnhealth.StatusFile {
		log.Fatal("OPENVPN_HEALTH_FILE must use the fixed private runtime path")
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
			log.Printf("OpenVPN health check failed: %v", err)
		} else if err := openvpnhealth.Publish(healthFile, time.Now().UTC()); err != nil {
			log.Fatalf("publish OpenVPN health: %v", err)
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
