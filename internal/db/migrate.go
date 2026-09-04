package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations
var migrationsFS embed.FS

func RunMigrations(databaseURL string) error {
	d, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return err
	}

	m, err := migrate.NewWithSourceInstance("iofs", d, databaseURL)
	if err != nil {
		return err
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	v, dirty, _ := m.Version()
	slog.Info("migrations applied", "version", v, "dirty", dirty)
	return nil
}

// RunMigrationsWithRetry waits for the direct PostgreSQL endpoint to become
// available during startup. Migrations deliberately bypass PgBouncer and run
// with a role that is distinct from the application runtime role.
func RunMigrationsWithRetry(ctx context.Context, databaseURL string) error {
	var lastErr error
	for attempt := 1; ; attempt++ {
		if err := RunMigrations(databaseURL); err == nil {
			return nil
		} else {
			lastErr = err
		}
		slog.Warn("PostgreSQL is not ready for migrations; retrying", "attempt", attempt, "error", lastErr)

		timer := time.NewTimer(databaseRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("run database migrations: %w: %v", ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}
