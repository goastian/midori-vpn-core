package repo

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

type ServerRepo struct {
	pool *pgxpool.Pool
}

func NewServerRepo(pool *pgxpool.Pool) *ServerRepo {
	return &ServerRepo{pool: pool}
}

func (r *ServerRepo) Create(ctx context.Context, s *models.VPNServer) error {
	query := `
		INSERT INTO vpn_servers (name, host, port, wg_port, public_key, core_token, location, country_code, max_peers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at
	`
	return r.pool.QueryRow(ctx, query,
		s.Name, s.Host, s.Port, s.WGPort, s.PublicKey, s.CoreToken,
		s.Location, s.CountryCode, s.MaxPeers,
	).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)
}

func (r *ServerRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.VPNServer, error) {
	query := `
		SELECT id, name, host, port, wg_port, public_key, core_token, location, country_code,
		       max_peers, current_peers, is_active, created_at, updated_at
		FROM vpn_servers WHERE id = $1
	`
	var s models.VPNServer
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID, &s.Name, &s.Host, &s.Port, &s.WGPort, &s.PublicKey, &s.CoreToken,
		&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get server: %w", err)
	}
	return &s, nil
}

func (r *ServerRepo) ListActive(ctx context.Context) ([]models.VPNServer, error) {
	query := `
		SELECT id, name, host, port, wg_port, public_key, location, country_code,
		       max_peers, current_peers, is_active, created_at, updated_at
		FROM vpn_servers WHERE is_active = TRUE ORDER BY name
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list servers: %w", err)
	}
	defer rows.Close()

	var servers []models.VPNServer
	for rows.Next() {
		var s models.VPNServer
		if err := rows.Scan(
			&s.ID, &s.Name, &s.Host, &s.Port, &s.WGPort, &s.PublicKey,
			&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive,
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}
	return servers, nil
}

func (r *ServerRepo) ListAll(ctx context.Context) ([]models.VPNServer, error) {
	query := `
		SELECT id, name, host, port, wg_port, public_key, core_token, location, country_code,
		       max_peers, current_peers, is_active, created_at, updated_at
		FROM vpn_servers ORDER BY name
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list all servers: %w", err)
	}
	defer rows.Close()

	var servers []models.VPNServer
	for rows.Next() {
		var s models.VPNServer
		if err := rows.Scan(
			&s.ID, &s.Name, &s.Host, &s.Port, &s.WGPort, &s.PublicKey, &s.CoreToken,
			&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive,
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}
	return servers, nil
}

func (r *ServerRepo) LeastLoaded(ctx context.Context) (*models.VPNServer, error) {
	query := `
		SELECT id, name, host, port, wg_port, public_key, core_token, location, country_code,
		       max_peers, current_peers, is_active, created_at, updated_at
		FROM vpn_servers
		WHERE is_active = TRUE AND current_peers < max_peers
		ORDER BY (current_peers::float / GREATEST(max_peers, 1)) ASC
		LIMIT 1
	`
	var s models.VPNServer
	err := r.pool.QueryRow(ctx, query).Scan(
		&s.ID, &s.Name, &s.Host, &s.Port, &s.WGPort, &s.PublicKey, &s.CoreToken,
		&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("no available server: %w", err)
	}
	return &s, nil
}

func (r *ServerRepo) Update(ctx context.Context, s *models.VPNServer) error {
	query := `
		UPDATE vpn_servers
		SET name = $1, host = $2, port = $3, wg_port = $4, public_key = $5, core_token = $6,
		    location = $7, country_code = $8, max_peers = $9, is_active = $10, updated_at = NOW()
		WHERE id = $11
	`
	_, err := r.pool.Exec(ctx, query,
		s.Name, s.Host, s.Port, s.WGPort, s.PublicKey, s.CoreToken,
		s.Location, s.CountryCode, s.MaxPeers, s.IsActive, s.ID,
	)
	return err
}

func (r *ServerRepo) UpdatePeerCount(ctx context.Context, serverID uuid.UUID, delta int) error {
	query := `UPDATE vpn_servers SET current_peers = GREATEST(current_peers + $1, 0), updated_at = NOW() WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, delta, serverID)
	return err
}

func (r *ServerRepo) SetPeerCount(ctx context.Context, serverID uuid.UUID, count int) error {
	query := `UPDATE vpn_servers SET current_peers = $1, updated_at = NOW() WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, count, serverID)
	return err
}

func (r *ServerRepo) Count(ctx context.Context) (int, int, error) {
	var total, active int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active = TRUE) FROM vpn_servers`).Scan(&total, &active)
	return total, active, err
}

func (r *ServerRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM vpn_servers WHERE id = $1`, id)
	return err
}
