package repo

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

type ServerRepo struct {
	pool *pgxpool.Pool

	// In-memory cache for active server list
	cacheMu      sync.RWMutex
	cachedActive []models.VPNServer
	cacheTime    time.Time
	cacheTTL     time.Duration
}

func NewServerRepo(pool *pgxpool.Pool) *ServerRepo {
	return &ServerRepo{
		pool:     pool,
		cacheTTL: 30 * time.Second,
	}
}

// InvalidateCache forces the next ListActive call to query the DB.
func (r *ServerRepo) InvalidateCache() {
	r.cacheMu.Lock()
	r.cacheTime = time.Time{}
	r.cacheMu.Unlock()
}

func (r *ServerRepo) Create(ctx context.Context, s *models.VPNServer) error {
	defer r.InvalidateCache()
	query := `
		INSERT INTO vpn_servers (name, host, endpoint, port, wg_port, public_key, core_token, location, country_code, max_peers, proxy_port)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, created_at, updated_at
	`
	return r.pool.QueryRow(ctx, query,
		s.Name, s.Host, s.Endpoint, s.Port, s.WGPort, s.PublicKey, s.CoreToken,
		s.Location, s.CountryCode, s.MaxPeers, s.ProxyPort,
	).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)
}

func (r *ServerRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.VPNServer, error) {
	query := `
		SELECT id, name, host, endpoint, port, wg_port, public_key, core_token, location, country_code,
		       max_peers, current_peers, is_active, proxy_port, created_at, updated_at
		FROM vpn_servers WHERE id = $1
	`
	var s models.VPNServer
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID, &s.Name, &s.Host, &s.Endpoint, &s.Port, &s.WGPort, &s.PublicKey, &s.CoreToken,
		&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive, &s.ProxyPort,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get server: %w", err)
	}
	return &s, nil
}

func (r *ServerRepo) ListActive(ctx context.Context) ([]models.VPNServer, error) {
	// Check cache first
	r.cacheMu.RLock()
	if r.cachedActive != nil && time.Since(r.cacheTime) < r.cacheTTL {
		result := make([]models.VPNServer, len(r.cachedActive))
		copy(result, r.cachedActive)
		r.cacheMu.RUnlock()
		return result, nil
	}
	r.cacheMu.RUnlock()

	query := `
		SELECT id, name, host, endpoint, port, wg_port, public_key, location, country_code,
		       max_peers, current_peers, is_active, proxy_port, created_at, updated_at
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
			&s.ID, &s.Name, &s.Host, &s.Endpoint, &s.Port, &s.WGPort, &s.PublicKey,
			&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive, &s.ProxyPort,
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list servers rows: %w", err)
	}

	// Update cache
	r.cacheMu.Lock()
	r.cachedActive = make([]models.VPNServer, len(servers))
	copy(r.cachedActive, servers)
	r.cacheTime = time.Now()
	r.cacheMu.Unlock()

	return servers, nil
}

func (r *ServerRepo) ListAll(ctx context.Context) ([]models.VPNServer, error) {
	query := `
		SELECT id, name, host, endpoint, port, wg_port, public_key, core_token, location, country_code,
		       max_peers, current_peers, is_active, proxy_port, created_at, updated_at
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
			&s.ID, &s.Name, &s.Host, &s.Endpoint, &s.Port, &s.WGPort, &s.PublicKey, &s.CoreToken,
			&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive, &s.ProxyPort,
			&s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list all servers rows: %w", err)
	}
	return servers, nil
}

func (r *ServerRepo) LeastLoaded(ctx context.Context) (*models.VPNServer, error) {
	query := `
		SELECT id, name, host, endpoint, port, wg_port, public_key, core_token, location, country_code,
		       max_peers, current_peers, is_active, proxy_port, created_at, updated_at
		FROM vpn_servers
		WHERE is_active = TRUE AND current_peers < max_peers
		ORDER BY (current_peers::float / GREATEST(max_peers, 1)) ASC
		LIMIT 1
	`
	var s models.VPNServer
	err := r.pool.QueryRow(ctx, query).Scan(
		&s.ID, &s.Name, &s.Host, &s.Endpoint, &s.Port, &s.WGPort, &s.PublicKey, &s.CoreToken,
		&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive, &s.ProxyPort,
		&s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("no available server: %w", err)
	}
	return &s, nil
}

func (r *ServerRepo) Update(ctx context.Context, s *models.VPNServer) error {
	defer r.InvalidateCache()
	query := `
		UPDATE vpn_servers
		SET name = $1, host = $2, endpoint = $3, port = $4, wg_port = $5, public_key = $6, core_token = $7,
		    location = $8, country_code = $9, max_peers = $10, is_active = $11, proxy_port = $12, updated_at = NOW()
		WHERE id = $13
	`
	_, err := r.pool.Exec(ctx, query,
		s.Name, s.Host, s.Endpoint, s.Port, s.WGPort, s.PublicKey, s.CoreToken,
		s.Location, s.CountryCode, s.MaxPeers, s.IsActive, s.ProxyPort, s.ID,
	)
	return err
}

func (r *ServerRepo) UpdatePeerCount(ctx context.Context, serverID uuid.UUID, delta int) error {
	defer r.InvalidateCache()
	query := `UPDATE vpn_servers SET current_peers = GREATEST(current_peers + $1, 0), updated_at = NOW() WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, delta, serverID)
	return err
}

// ReserveSlot atomically increments current_peers only if the server is active
// and has capacity. Returns true if a slot was reserved.
func (r *ServerRepo) ReserveSlot(ctx context.Context, serverID uuid.UUID) (bool, error) {
	defer r.InvalidateCache()
	query := `
		UPDATE vpn_servers
		SET current_peers = current_peers + 1, updated_at = NOW()
		WHERE id = $1 AND is_active = TRUE AND current_peers < max_peers
	`
	tag, err := r.pool.Exec(ctx, query, serverID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *ServerRepo) SetPeerCount(ctx context.Context, serverID uuid.UUID, count int) error {
	defer r.InvalidateCache()
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
	defer r.InvalidateCache()
	_, err := r.pool.Exec(ctx, `DELETE FROM vpn_servers WHERE id = $1`, id)
	return err
}
