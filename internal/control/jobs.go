package control

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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

// StartStatsSync runs every 60s: syncs peer stats from all cores via REST
// and broadcasts updated stats to WebSocket clients.
func StartStatsSync(parentCtx context.Context, pool *pgxpool.Pool, hub *WSHub) {
	serverRepo := repo.NewServerRepo(pool)
	peerRepo := repo.NewPeerRepo(pool)

	slog.Info("job started", "job", "stats-sync", "interval", statsSyncInterval.String())
	ticker := time.NewTicker(statsSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-parentCtx.Done():
			slog.Info("job stopped", "job", "stats-sync")
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(parentCtx, statsSyncTimeout)

		servers, err := serverRepo.ListAll(ctx)
		if err != nil {
			slog.Error("stats-sync list servers error", "error", err)
			cancel()
			continue
		}

		for _, server := range servers {
			if !server.IsActive {
				continue
			}

			corePeers, err := CallCoreListPeers(&server)
			if err != nil {
				slog.Error("stats-sync core error", "server", server.Name, "host", server.Host, "error", err)
				continue
			}

			// Update server peer count from actual core data
			if err := serverRepo.SetPeerCount(ctx, server.ID, len(corePeers)); err != nil {
				slog.Error("stats-sync set peer count error", "server", server.Name, "error", err)
			}

			// Match core peers with DB peers and update stats
			dbPeers, err := peerRepo.ListActiveByServer(ctx, server.ID)
			if err != nil {
				continue
			}

			peerMap := make(map[string]*CorePeerStatsResponse, len(corePeers))
			for i := range corePeers {
				peerMap[corePeers[i].PublicKey] = &corePeers[i]
			}

			for _, dbPeer := range dbPeers {
				if stats, ok := peerMap[dbPeer.PublicKey]; ok {
					var hs *time.Time
					if stats.LastHandshake != "" {
						if t, err := time.Parse(time.RFC3339, stats.LastHandshake); err == nil && !t.IsZero() {
							hs = &t
						}
					}
					if err := peerRepo.UpdateStats(ctx, dbPeer.ID, stats.BytesSent, stats.BytesReceived, hs); err != nil {
						slog.Error("stats-sync update stats error", "peer_id", dbPeer.ID, "error", err)
					}
				}
			}

			slog.Info("stats-sync completed", "server", server.Name, "core_peers", len(corePeers), "db_peers", len(dbPeers))
		}

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
			if err == nil {
				if err := CallCoreRemovePeer(server, peer.PublicKey); err != nil {
					slog.Error("peer-cleanup core remove error", "peer_id", peer.ID, "error", err)
				}
				if err := serverRepo.UpdatePeerCount(ctx, peer.ServerID, -1); err != nil {
					slog.Error("peer-cleanup update peer count error", "server_id", peer.ServerID, "error", err)
				}
			}

			if err := peerRepo.Deactivate(ctx, peer.ID); err != nil {
				slog.Error("peer-cleanup deactivate error", "peer_id", peer.ID, "error", err)
			}

			auditRepo.Log(ctx, &peer.UserID, "peer.cleanup",
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
