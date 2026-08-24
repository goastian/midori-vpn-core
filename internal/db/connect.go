package db

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/config"
)

const databaseRetryInterval = 2 * time.Second

// Connect waits for PostgreSQL to become ready while the application is
// starting. Container startup order only guarantees that the PostgreSQL
// process exists, not that it is already accepting connections.
func Connect(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	return connectWithRetry(ctx, cfg, databaseRetryInterval)
}

func connectWithRetry(ctx context.Context, cfg *config.Config, retryInterval time.Duration) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	poolCfg.MaxConns = 25
	poolCfg.MinConns = 4
	poolCfg.MaxConnLifetime = 1 * time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute
	poolCfg.HealthCheckPeriod = 1 * time.Minute

	var lastErr error
	for attempt := 1; ; attempt++ {
		pool, createErr := pgxpool.NewWithConfig(ctx, poolCfg)
		if createErr == nil {
			if pingErr := pool.Ping(ctx); pingErr == nil {
				return pool, nil
			} else {
				lastErr = fmt.Errorf("ping database: %w", pingErr)
			}
			pool.Close()
		} else {
			lastErr = fmt.Errorf("create pool: %w", createErr)
		}

		slog.Warn("PostgreSQL is not ready; retrying", "attempt", attempt, "error", lastErr)
		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("connect database: %w: %v", ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}
