package control

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

const (
	statsSyncInterval          = 60 * time.Second
	statsSyncTimeout           = 30 * time.Second
	sessionMeshCleanupInterval = time.Hour
	sessionMeshStaleWindow     = 2 * time.Hour
	sessionMeshCleanupTimeout  = 30 * time.Second
	peerCleanupInterval        = 5 * time.Minute
	peerCleanupStaleWindow     = 30 * time.Minute
	peerCleanupTimeout         = 60 * time.Second
)

// StartStatsSync reconciles immediately and every 60 seconds, then broadcasts
// the resulting aggregate statistics to WebSocket clients.
func StartStatsSync(parentCtx context.Context, pool *pgxpool.Pool, hub *WSHub, dataCipher ...*dataencryption.Cipher) {
	serverRepo := repo.NewServerRepo(pool)
	peerRepo := repo.NewPeerRepo(pool)
	reconciler := NewReconciler(pool, nil, firstReconcilerCipher(dataCipher))

	slog.Info("job started", "job", "peer-reconciliation", "interval", statsSyncInterval.String())
	ticker := time.NewTicker(statsSyncInterval)
	defer ticker.Stop()

	for {
		ctx, cancel := context.WithTimeout(parentCtx, statsSyncTimeout)
		report := reconciler.RunOnce(ctx)
		slog.Info("peer reconciliation completed",
			"observed_servers", report.ObservedServers,
			"observation_errors", report.ObservationErrors,
			"divergent_peers", report.DivergentPeers,
			"orphans_removed", report.OrphansRemoved,
			"cleanup_pending", report.CleanupPending,
			"pending_operations", report.PendingOperations)

		// Broadcast updated stats to WS clients
		if hub != nil && hub.ClientCount() > 0 {
			userRepo := repo.NewUserRepo(pool)

			totalUsers, _ := userRepo.Count(ctx)
			totalServers, activeServers, _ := serverRepo.Count(ctx)
			totalPeers, activePeers, _ := peerRepo.CountAll(ctx)
			bytesSent, bytesRecv, _ := peerRepo.TotalTraffic(ctx)

			hub.Broadcast(map[string]interface{}{
				"type": "stats",
				"data": map[string]interface{}{
					"total_users":          totalUsers,
					"total_servers":        totalServers,
					"active_servers":       activeServers,
					"total_peers":          totalPeers,
					"active_peers":         activePeers,
					"total_bytes_sent":     bytesSent,
					"total_bytes_received": bytesRecv,
				},
			})
		}

		cancel()
		select {
		case <-parentCtx.Done():
			slog.Info("job stopped", "job", "peer-reconciliation")
			return
		case <-ticker.C:
		}
	}
}

// StartSessionMeshCleanup runs every hour and removes session meshes that
// have not been updated in the last 2 hours. This reclaims orphaned session
// meshes when the extension is closed without calling DELETE /mesh/auto.
func StartSessionMeshCleanup(parentCtx context.Context, pool *pgxpool.Pool) {
	meshRepo := repo.NewMeshRepo(pool)

	slog.Info("job started", "job", "session-mesh-cleanup", "interval", sessionMeshCleanupInterval.String(), "stale_threshold", sessionMeshStaleWindow.String())
	ticker := time.NewTicker(sessionMeshCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-parentCtx.Done():
			slog.Info("job stopped", "job", "session-mesh-cleanup")
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(parentCtx, sessionMeshCleanupTimeout)

		deleted, err := meshRepo.DeleteStaleSessions(ctx, sessionMeshStaleWindow)
		if err != nil {
			slog.Error("session-mesh-cleanup error", "error", err)
		} else if deleted > 0 {
			slog.Info("session-mesh-cleanup removed stale sessions", "count", deleted)
		}

		cancel()
	}
}

func StartPeerCleanup(parentCtx context.Context, pool *pgxpool.Pool) {
	serverRepo := repo.NewServerRepo(pool)
	peerRepo := repo.NewPeerRepo(pool)
	auditRepo := repo.NewAuditRepo(pool)

	slog.Info("job started", "job", "peer-cleanup", "interval", peerCleanupInterval.String(), "stale_threshold", peerCleanupStaleWindow.String())
	ticker := time.NewTicker(peerCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-parentCtx.Done():
			slog.Info("job stopped", "job", "peer-cleanup")
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(parentCtx, peerCleanupTimeout)

		stalePeers, err := peerRepo.ListStale(ctx, peerCleanupStaleWindow)
		if err != nil {
			slog.Error("peer-cleanup list stale error", "error", err)
			cancel()
			continue
		}

		if len(stalePeers) == 0 {
			cancel()
			continue
		}

		slog.Info("peer-cleanup found stale peers", "count", len(stalePeers))

		for _, peer := range stalePeers {
			server, err := serverRepo.GetByID(ctx, peer.ServerID)
			if err != nil {
				slog.Error("peer-cleanup load server error", "peer_id", peer.ID, "error", err)
				continue
			}
			expectedOperationID := ""
			if peer.ProvisionOperationID != nil {
				expectedOperationID = peer.ProvisionOperationID.String()
			} else {
				observed, err := CallCoreGetPeerStatsContext(ctx, server, peer.PublicKey)
				if coreErrorHasStatus(err, 404) {
					observed = nil
				} else if err != nil {
					slog.Error("peer-cleanup Core observation error", "peer_id", peer.ID, "error", err)
					continue
				}
				if observed != nil {
					expectedOperationID = observed.OperationID
					if expectedOperationID == "" {
						slog.Error("peer-cleanup Core owner unavailable", "peer_id", peer.ID)
						continue
					}
				}
			}
			if expectedOperationID != "" {
				if err := CallCoreRemovePeerContext(ctx, server, peer.PublicKey, expectedOperationID); err != nil {
					slog.Error("peer-cleanup Core remove error", "peer_id", peer.ID, "error", err)
					continue
				}
			}
			deactivated, err := peerRepo.DeactivateAndRecount(ctx, peer.ID)
			if err != nil {
				slog.Error("peer-cleanup transactional deactivate error", "peer_id", peer.ID, "error", err)
				continue
			}
			if !deactivated {
				continue
			}

			auditRepo.LogBestEffort(ctx, &peer.UserID, "peer.cleanup",
				map[string]interface{}{
					"peer_id":   peer.ID,
					"server_id": peer.ServerID,
					"reason":    "stale_or_expired",
				}, "system")

			slog.Info("peer-cleanup deactivated peer", "peer_id", peer.ID, "user_id", peer.UserID, "server_id", peer.ServerID)
		}

		cancel()
	}
}
