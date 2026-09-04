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

func TestDatabasePoolLimits(t *testing.T) {
	maxConns, minConns := databasePoolLimits(&config.Config{})
	if maxConns != defaultPoolMaxConns || minConns != defaultPoolMinConns {
		t.Fatalf("databasePoolLimits(default) = (%d, %d), want (%d, %d)",
			maxConns, minConns, defaultPoolMaxConns, defaultPoolMinConns)
	}

	maxConns, minConns = databasePoolLimits(&config.Config{
		DatabasePoolMaxConns: 24,
		DatabasePoolMinConns: 3,
	})
	if maxConns != 24 || minConns != 3 {
		t.Fatalf("databasePoolLimits(configured) = (%d, %d), want (24, 3)", maxConns, minConns)
	}
}

func TestValidateRuntimeSettings(t *testing.T) {
	if err := validateRuntimeSettings("5s", "2s", "30s", "pg_catalog, public"); err != nil {
		t.Fatalf("validateRuntimeSettings() rejected hardened role: %v", err)
	}

	tests := []struct {
		name             string
		statementTimeout string
		lockTimeout      string
		idleTxTimeout    string
		searchPath       string
	}{
		{name: "statement timeout", statementTimeout: "0", lockTimeout: "2s", idleTxTimeout: "30s", searchPath: "pg_catalog, public"},
		{name: "lock timeout", statementTimeout: "5s", lockTimeout: "0", idleTxTimeout: "30s", searchPath: "pg_catalog, public"},
		{name: "idle transaction timeout", statementTimeout: "5s", lockTimeout: "2s", idleTxTimeout: "0", searchPath: "pg_catalog, public"},
		{name: "search path", statementTimeout: "5s", lockTimeout: "2s", idleTxTimeout: "30s", searchPath: `"$user", public`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRuntimeSettings(test.statementTimeout, test.lockTimeout, test.idleTxTimeout, test.searchPath); err == nil {
				t.Fatal("validateRuntimeSettings() accepted an unsafe runtime setting")
			}
		})
	}
}
