package api

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/repo"
)

// StartStatsSync runs every 60s: syncs peer stats from all cores via REST
// and broadcasts updated stats to WebSocket clients.
func StartStatsSync(pool *pgxpool.Pool, hub *WSHub) {
	serverRepo := repo.NewServerRepo(pool)
	peerRepo := repo.NewPeerRepo(pool)

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	log.Println("job: stats-sync started (interval=60s)")

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		servers, err := serverRepo.ListAll(ctx)
		if err != nil {
			log.Printf("job: stats-sync list servers error: %v", err)
			cancel()
			continue
		}

		for _, server := range servers {
			if !server.IsActive {
				continue
			}

			corePeers, err := callCoreListPeers(&server)
			if err != nil {
				log.Printf("job: stats-sync core %s (%s) error: %v", server.Name, server.Host, err)
				continue
			}

			// Update server peer count from actual core data
			_ = serverRepo.SetPeerCount(ctx, server.ID, len(corePeers))

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
						if t, err := time.Parse(time.RFC3339, stats.LastHandshake); err == nil {
							hs = &t
						}
					}
					_ = peerRepo.UpdateStats(ctx, dbPeer.ID, stats.BytesSent, stats.BytesReceived, hs)
				}
			}

			log.Printf("job: stats-sync %s: %d core peers, %d db peers", server.Name, len(corePeers), len(dbPeers))
		}

		// Broadcast updated stats to WS clients
		if hub != nil && hub.ClientCount() > 0 {
			userRepo := repo.NewUserRepo(pool)
			subRepo := repo.NewSubscriptionRepo(pool)

			totalUsers, _ := userRepo.Count(ctx)
			totalServers, activeServers, _ := serverRepo.Count(ctx)
			totalPeers, activePeers, _ := peerRepo.CountAll(ctx)
			totalSubs, _ := subRepo.CountActive(ctx)
			bytesSent, bytesRecv, _ := peerRepo.TotalTraffic(ctx)

			hub.Broadcast(map[string]interface{}{
				"type": "stats",
				"data": map[string]interface{}{
					"total_users":         totalUsers,
					"total_servers":       totalServers,
					"active_servers":      activeServers,
					"total_peers":         totalPeers,
					"active_peers":        activePeers,
					"total_subscriptions": totalSubs,
					"total_bytes_sent":    bytesSent,
					"total_bytes_received": bytesRecv,
				},
			})
		}

		cancel()
	}
}

// StartPeerCleanup runs every 5min: deactivates expired peers or peers
// without a handshake in the last 30 minutes.
func StartPeerCleanup(pool *pgxpool.Pool) {
	serverRepo := repo.NewServerRepo(pool)
	peerRepo := repo.NewPeerRepo(pool)
	auditRepo := repo.NewAuditRepo(pool)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	log.Println("job: peer-cleanup started (interval=5min, stale_threshold=30min)")

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

		stalePeers, err := peerRepo.ListStale(ctx, 30*time.Minute)
		if err != nil {
			log.Printf("job: peer-cleanup list stale error: %v", err)
			cancel()
			continue
		}

		if len(stalePeers) == 0 {
			cancel()
			continue
		}

		log.Printf("job: peer-cleanup found %d stale peers", len(stalePeers))

		for _, peer := range stalePeers {
			server, err := serverRepo.GetByID(ctx, peer.ServerID)
			if err == nil {
				_ = callCoreRemovePeer(server, peer.PublicKey)
				_ = serverRepo.UpdatePeerCount(ctx, peer.ServerID, -1)
			}

			_ = peerRepo.Deactivate(ctx, peer.ID)

			auditRepo.Log(ctx, &peer.UserID, "peer.cleanup",
				map[string]interface{}{
					"peer_id":   peer.ID,
					"server_id": peer.ServerID,
					"reason":    "stale_or_expired",
				}, "system")

			log.Printf("job: peer-cleanup deactivated peer %s (user=%s, server=%s)",
				peer.ID, peer.UserID, peer.ServerID)
		}

		cancel()
	}
}
