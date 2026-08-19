package api

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/respond"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

var startTime = time.Now()

type HealthChecker struct {
	cfg  *config.Config
	mgr  *wg.Manager
	pool *pgxpool.Pool
}

func NewHealthChecker(cfg *config.Config, mgr *wg.Manager, pool *pgxpool.Pool) *HealthChecker {
	return &HealthChecker{cfg: cfg, mgr: mgr, pool: pool}
}

func (h *HealthChecker) Livez(w http.ResponseWriter, r *http.Request) {
	respond.JsonOK(w, map[string]interface{}{
		"status":         "alive",
		"uptime_seconds": int64(time.Since(startTime).Seconds()),
	}, http.StatusOK)
}

func (h *HealthChecker) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	checks := make(map[string]interface{})
	isReady := true

	// Check PostgreSQL
	if h.pool != nil {
		pgStart := time.Now()
		if err := h.pool.Ping(ctx); err != nil {
			isReady = false
			checks["postgres"] = map[string]interface{}{
				"status": "error",
				"error":  "database connection failed",
			}
		} else {
			checks["postgres"] = map[string]interface{}{
				"status":     "ok",
				"latency_ms": time.Since(pgStart).Milliseconds(),
			}
		}
	}

	// Check WireGuard Interface
	if h.mgr != nil {
		stats, err := h.mgr.ServerStats()
		if err != nil {
			isReady = false
			checks["wireguard"] = map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			}
		} else {
			checks["wireguard"] = map[string]interface{}{
				"status":    "ok",
				"interface": stats.Interface,
			}
		}
	}

	status := "ready"
	httpCode := http.StatusOK
	if !isReady {
		status = "degraded"
		httpCode = http.StatusServiceUnavailable
	}

	respond.JsonOK(w, map[string]interface{}{
		"status": status,
		"checks": checks,
	}, httpCode)
}
