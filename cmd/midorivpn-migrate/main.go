package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/db"
)

func main() {
	databaseURL := config.MigrationDatabaseURLFromEnv()
	if databaseURL == "" {
		log.Fatal("MIGRATION_DATABASE_URL or the POSTGRES_MIGRATOR_* settings are required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := db.RunMigrationsWithRetry(ctx, databaseURL); err != nil {
		log.Fatalf("database migration failed: %v", err)
	}
}
