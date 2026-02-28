package repo

import (
	"context"
	"fmt"

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
		INSERT INTO peers (user_id, server_id, public_key, assigned_ip)
		VALUES ($1, $2, $3, $4)
		RETURNING id, is_active, created_at
	`
	return r.pool.QueryRow(ctx, query,
		p.UserID, p.ServerID, p.PublicKey, p.AssignedIP,
	).Scan(&p.ID, &p.IsActive, &p.CreatedAt)
}

func (r *PeerRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, assigned_ip, is_active,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers WHERE id = $1
	`
	var p models.Peer
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive,
		&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get peer: %w", err)
	}
	return &p, nil
}

func (r *PeerRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, assigned_ip, is_active,
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
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive,
			&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
		); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	return peers, nil
}

func (r *PeerRepo) ListByServer(ctx context.Context, serverID uuid.UUID) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, assigned_ip, is_active,
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
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.AssignedIP, &p.IsActive,
			&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
		); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	return peers, nil
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
