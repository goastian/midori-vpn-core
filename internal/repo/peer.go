package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

type PeerRepo struct {
	pool *pgxpool.Pool
}

func NewPeerRepo(pool *pgxpool.Pool) *PeerRepo {
	return &PeerRepo{pool: pool}
}

func (r *PeerRepo) Create(ctx context.Context, p *models.Peer) error {
	query := `
		INSERT INTO peers (user_id, server_id, public_key, assigned_ip, device_name)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, is_active, created_at
	`
	return r.pool.QueryRow(ctx, query,
		p.UserID, p.ServerID, p.PublicKey, p.AssignedIP, p.DeviceName,
	).Scan(&p.ID, &p.IsActive, &p.CreatedAt)
}

func (r *PeerRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, assigned_ip, is_active, device_name,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers WHERE id = $1
	`
	var p models.Peer
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive, &p.DeviceName,
		&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get peer: %w", err)
	}
	return &p, nil
}

func (r *PeerRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, assigned_ip, is_active, device_name,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers WHERE user_id = $1 ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list peers by user: %w", err)
	}
	defer rows.Close()

	var peers []models.Peer
	for rows.Next() {
		var p models.Peer
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive, &p.DeviceName,
			&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
		); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list peers by user rows: %w", err)
	}
	return peers, nil
}

func (r *PeerRepo) ListByServer(ctx context.Context, serverID uuid.UUID) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, assigned_ip, is_active, device_name,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers WHERE server_id = $1 ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query, serverID)
	if err != nil {
		return nil, fmt.Errorf("list peers by server: %w", err)
	}
	defer rows.Close()

	var peers []models.Peer
	for rows.Next() {
		var p models.Peer
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive, &p.DeviceName,
			&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
		); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list peers by server rows: %w", err)
	}
	return peers, nil
}

func (r *PeerRepo) ListAll(ctx context.Context, limit, offset int) ([]models.Peer, error) {
	query := `
		SELECT p.id, p.user_id, COALESCE(u.email, ''), p.server_id, p.public_key, p.assigned_ip,
		       p.is_active, p.device_name, p.last_handshake, p.bytes_sent, p.bytes_received,
		       p.created_at, p.expires_at
		FROM peers p
		LEFT JOIN users u ON u.id = p.user_id
		ORDER BY p.created_at DESC LIMIT $1 OFFSET $2
	`
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list all peers: %w", err)
	}
	defer rows.Close()

	var peers []models.Peer
	for rows.Next() {
		var p models.Peer
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.UserEmail, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive, &p.DeviceName,
			&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
		); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list all peers rows: %w", err)
	}
	return peers, nil
}

func (r *PeerRepo) ListActiveByServer(ctx context.Context, serverID uuid.UUID) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, assigned_ip, is_active, device_name,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers WHERE server_id = $1 AND is_active = TRUE ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query, serverID)
	if err != nil {
		return nil, fmt.Errorf("list active peers by server: %w", err)
	}
	defer rows.Close()

	var peers []models.Peer
	for rows.Next() {
		var p models.Peer
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive, &p.DeviceName,
			&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
		); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active peers rows: %w", err)
	}
	return peers, nil
}

func (r *PeerRepo) ListStale(ctx context.Context, noHandshakeSince time.Duration) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, assigned_ip, is_active, device_name,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers
		WHERE is_active = TRUE
		  AND (
		    (expires_at IS NOT NULL AND expires_at < NOW())
		    OR (last_handshake IS NOT NULL AND last_handshake < NOW() - $1::interval)
		    OR (last_handshake IS NULL AND created_at < NOW() - $1::interval)
		  )
	`
	rows, err := r.pool.Query(ctx, query, fmt.Sprintf("%d seconds", int(noHandshakeSince.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("list stale peers: %w", err)
	}
	defer rows.Close()

	var peers []models.Peer
	for rows.Next() {
		var p models.Peer
		if err := rows.Scan(
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive, &p.DeviceName,
			&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
		); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list stale peers rows: %w", err)
	}
	return peers, nil
}

func (r *PeerRepo) UpdateStats(ctx context.Context, id uuid.UUID, bytesSent, bytesRecv int64, lastHandshake *time.Time) error {
	query := `UPDATE peers SET bytes_sent = $1, bytes_received = $2, last_handshake = $3 WHERE id = $4`
	_, err := r.pool.Exec(ctx, query, bytesSent, bytesRecv, lastHandshake, id)
	return err
}

func (r *PeerRepo) Deactivate(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE peers SET is_active = FALSE WHERE id = $1`, id)
	return err
}

func (r *PeerRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM peers WHERE id = $1`, id)
	return err
}

func (r *PeerRepo) CountByUser(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM peers WHERE user_id = $1 AND is_active = TRUE`, userID).Scan(&count)
	return count, err
}

func (r *PeerRepo) CountAll(ctx context.Context) (int, int, error) {
	var total, active int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active = TRUE) FROM peers`).Scan(&total, &active)
	return total, active, err
}

func (r *PeerRepo) TotalTraffic(ctx context.Context) (int64, int64, error) {
	var sent, recv int64
	err := r.pool.QueryRow(ctx, `SELECT COALESCE(SUM(bytes_sent),0), COALESCE(SUM(bytes_received),0) FROM peers`).Scan(&sent, &recv)
	return sent, recv, err
}
