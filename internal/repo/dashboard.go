package repo

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

const dashboardRecentSessionLimit = 6

type DashboardRepo struct {
	pool *pgxpool.Pool
}

type DashboardUserSnapshot struct {
	RegisteredDevices int
	ConnectedDevices  int
	Traffic           models.DashboardTraffic
	RecentSessions    []models.DashboardRecentSession
}

func NewDashboardRepo(pool *pgxpool.Pool) *DashboardRepo {
	return &DashboardRepo{pool: pool}
}

// UserSnapshot returns device, traffic, and recent-session values from one
// repeatable-read snapshot. Revoked devices remain counted only while an
// active session is still converging, so a completed deletion does not inflate
// the registered-device total while pending access remains visible.
func (r *DashboardRepo) UserSnapshot(ctx context.Context, userID uuid.UUID) (*DashboardUserSnapshot, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("begin dashboard snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	snapshot := &DashboardUserSnapshot{
		RecentSessions: make([]models.DashboardRecentSession, 0, dashboardRecentSessionLimit),
	}
	if err := tx.QueryRow(ctx, `
		SELECT
			(
				SELECT COUNT(*)
				FROM devices device
				WHERE device.user_id = $1
				  AND (
					device.revoked_at IS NULL
					OR EXISTS (
						SELECT 1 FROM peers active_peer
						WHERE active_peer.device_id = device.id
						  AND active_peer.is_active = TRUE
					)
				  )
			),
			(
				SELECT COUNT(*)
				FROM devices device
				WHERE device.user_id = $1
				  AND EXISTS (
					SELECT 1 FROM peers active_peer
					WHERE active_peer.device_id = device.id
					  AND active_peer.is_active = TRUE
				  )
			),
			COALESCE(SUM(peer.bytes_sent), 0),
			COALESCE(SUM(peer.bytes_received), 0)
		FROM peers peer
		WHERE peer.user_id = $1`, userID).Scan(
		&snapshot.RegisteredDevices,
		&snapshot.ConnectedDevices,
		&snapshot.Traffic.BytesSent,
		&snapshot.Traffic.BytesReceived,
	); err != nil {
		return nil, fmt.Errorf("load dashboard aggregates: %w", err)
	}

	rows, err := tx.Query(ctx, `
		SELECT
			peer.id,
			peer.device_id,
			COALESCE(
				NULLIF(device.alias, ''),
				NULLIF(device.reported_name, ''),
				NULLIF(peer.device_name, ''),
				'Device'
			)::varchar(64),
			peer.server_id,
			server.name,
			'wireguard',
			peer.assigned_ip,
			peer.is_active,
			peer.bytes_sent,
			peer.bytes_received,
			peer.last_handshake,
			peer.created_at
		FROM peers peer
		LEFT JOIN devices device ON device.id = peer.device_id
		JOIN vpn_servers server ON server.id = peer.server_id
		WHERE peer.user_id = $1
		ORDER BY peer.created_at DESC, peer.id DESC
		LIMIT $2`, userID, dashboardRecentSessionLimit)
	if err != nil {
		return nil, fmt.Errorf("list dashboard recent sessions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var session models.DashboardRecentSession
		if err := rows.Scan(
			&session.ID,
			&session.DeviceID,
			&session.DeviceName,
			&session.ServerID,
			&session.ServerName,
			&session.Protocol,
			&session.AssignedIP,
			&session.IsActive,
			&session.BytesSent,
			&session.BytesReceived,
			&session.LastHandshake,
			&session.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan dashboard recent session: %w", err)
		}
		snapshot.RecentSessions = append(snapshot.RecentSessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list dashboard recent session rows: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit dashboard snapshot: %w", err)
	}
	return snapshot, nil
}

func (r *DashboardRepo) Infrastructure(ctx context.Context) (models.AdminStats, error) {
	var stats models.AdminStats
	err := r.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM users),
			(SELECT COUNT(*) FROM vpn_servers),
			(SELECT COUNT(*) FROM vpn_servers WHERE is_active = TRUE),
			(SELECT COUNT(*) FROM peers),
			(SELECT COUNT(*) FROM peers WHERE is_active = TRUE),
			(SELECT COALESCE(SUM(bytes_sent), 0) FROM peers),
			(SELECT COALESCE(SUM(bytes_received), 0) FROM peers)`).Scan(
		&stats.TotalUsers,
		&stats.TotalServers,
		&stats.ActiveServers,
		&stats.TotalPeers,
		&stats.ActivePeers,
		&stats.TotalBytesSent,
		&stats.TotalBytesRecv,
	)
	if err != nil {
		return models.AdminStats{}, fmt.Errorf("load dashboard infrastructure: %w", err)
	}
	return stats, nil
}
