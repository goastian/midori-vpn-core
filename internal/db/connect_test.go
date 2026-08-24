package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
)

func TestConnectRejectsInvalidDatabaseURL(t *testing.T) {
	_, err := Connect(context.Background(), &config.Config{DatabaseURL: "://invalid"})
	if err == nil || !strings.Contains(err.Error(), "parse database URL") {
		t.Fatalf("Connect() error = %v, want parse database URL error", err)
	}
}

func TestConnectStopsRetryingWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := connectWithRetry(ctx, &config.Config{
		DatabaseURL: "postgres://midori:secret@127.0.0.1:1/midori?sslmode=disable&connect_timeout=1",
	}, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("connectWithRetry() error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("connectWithRetry() took %s, want cancellation within one second", elapsed)
	}
}
