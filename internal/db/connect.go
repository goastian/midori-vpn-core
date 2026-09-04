package db

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/config"
)

const (
	databaseRetryInterval   = 2 * time.Second
	defaultPoolMaxConns     = 16
	defaultPoolMinConns     = 2
	runtimeStatementTimeout = "5s"
	runtimeLockTimeout      = "2s"
	runtimeIdleTxTimeout    = "30s"
)

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

	maxConns, minConns := databasePoolLimits(cfg)
	poolCfg.MaxConns = int32(maxConns)
	poolCfg.MinConns = int32(minConns)
	poolCfg.MaxConnLifetime = 1 * time.Hour
	poolCfg.MaxConnLifetimeJitter = 5 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute
	poolCfg.HealthCheckPeriod = 30 * time.Second
	if cfg.AppEnv == "production" {
		poolCfg.AfterConnect = verifyRuntimeConnection
	}

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

func databasePoolLimits(cfg *config.Config) (int, int) {
	maxConns := cfg.DatabasePoolMaxConns
	if maxConns == 0 {
		maxConns = defaultPoolMaxConns
	}
	minConns := cfg.DatabasePoolMinConns
	if cfg.DatabasePoolMaxConns == 0 && minConns == 0 {
		minConns = defaultPoolMinConns
	}
	return maxConns, minConns
}

func verifyRuntimeConnection(ctx context.Context, conn *pgx.Conn) error {
	var statementTimeout, lockTimeout, idleTxTimeout, searchPath string
	err := conn.QueryRow(ctx, `SELECT
		current_setting('statement_timeout'),
		current_setting('lock_timeout'),
		current_setting('idle_in_transaction_session_timeout'),
		current_setting('search_path')`).Scan(
		&statementTimeout, &lockTimeout, &idleTxTimeout, &searchPath,
	)
	if err != nil {
		return fmt.Errorf("read runtime database hardening settings: %w", err)
	}
	return validateRuntimeSettings(statementTimeout, lockTimeout, idleTxTimeout, searchPath)
}

func validateRuntimeSettings(statementTimeout, lockTimeout, idleTxTimeout, searchPath string) error {
	settings := []struct {
		name string
		got  string
		want string
	}{
		{name: "statement_timeout", got: statementTimeout, want: runtimeStatementTimeout},
		{name: "lock_timeout", got: lockTimeout, want: runtimeLockTimeout},
		{name: "idle_in_transaction_session_timeout", got: idleTxTimeout, want: runtimeIdleTxTimeout},
	}
	for _, setting := range settings {
		if setting.got != setting.want {
			return fmt.Errorf("runtime database role requires %s=%s", setting.name, setting.want)
		}
	}

	parts := strings.Split(searchPath, ",")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) != "pg_catalog" || strings.TrimSpace(parts[1]) != "public" {
		return fmt.Errorf("runtime database role requires search_path=pg_catalog,public")
	}
	return nil
}
