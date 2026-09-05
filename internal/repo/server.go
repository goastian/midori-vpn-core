package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

var ErrServerNotDrained = errors.New("server still has active sessions or operations")

type ServerRepo struct {
	pool *pgxpool.Pool

	// In-memory cache for active server list
	cacheMu      sync.RWMutex
	cachedActive []models.VPNServer
	cacheTime    time.Time
	cacheTTL     time.Duration
}

const serverColumns = `id, node_id, legacy_node_unbound, name, host, probe_url, endpoint, port, wg_port, public_key, location, country_code,
	max_peers, current_peers, is_active, draining_at, created_at, updated_at`

type rowScanner interface {
	Scan(dest ...interface{}) error
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
		INSERT INTO vpn_servers (node_id, legacy_node_unbound, name, host, probe_url, endpoint, port, wg_port, public_key, location, country_code, max_peers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at, updated_at
	`
	return r.pool.QueryRow(ctx, query,
		s.NodeID, s.LegacyNodeUnbound, s.Name, s.Host, s.ProbeURL, s.Endpoint, s.Port,
		s.WGPort, s.PublicKey, s.Location, s.CountryCode, s.MaxPeers,
	).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)
}

// CreateWithTransports persists the server and its advertised transports in a
// single transaction so a server can never become visible with a partial
// transport contract.
func (r *ServerRepo) CreateWithTransports(ctx context.Context, s *models.VPNServer, transports []models.TransportCapability) error {
	if len(transports) == 0 {
		return errors.New("server must have at least one transport")
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin create server: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `
		INSERT INTO vpn_servers (node_id, legacy_node_unbound, name, host, probe_url, endpoint, port, wg_port, public_key, location, country_code, max_peers, is_active, draining_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, created_at, updated_at`,
		s.NodeID, s.LegacyNodeUnbound, s.Name, s.Host, s.ProbeURL, s.Endpoint, s.Port,
		s.WGPort, s.PublicKey, s.Location, s.CountryCode, s.MaxPeers,
		s.IsActive, s.DrainingAt,
	).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return fmt.Errorf("create server: %w", err)
	}
	if err := replaceTransportsTx(ctx, tx, s.ID, transports); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit server creation: %w", err)
	}
	r.InvalidateCache()
	return nil
}

func (r *ServerRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.VPNServer, error) {
	query := `SELECT ` + serverColumns + ` FROM vpn_servers WHERE id = $1`
	s, err := scanServer(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("get server: %w", err)
	}
	// loadTransports receives a value slice so assign through a single-item copy.
	servers := []models.VPNServer{*s}
	if err := r.loadTransports(ctx, servers); err != nil {
		return nil, err
	}
	*s = servers[0]
	return s, nil
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

	query := `SELECT ` + serverColumns + ` FROM vpn_servers WHERE is_active = TRUE ORDER BY name`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list servers: %w", err)
	}
	defer rows.Close()

	var servers []models.VPNServer
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		servers = append(servers, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list servers rows: %w", err)
	}
	if err := r.loadTransports(ctx, servers); err != nil {
		return nil, err
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
	query := `SELECT ` + serverColumns + ` FROM vpn_servers ORDER BY name`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list all servers: %w", err)
	}
	defer rows.Close()

	var servers []models.VPNServer
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		servers = append(servers, *s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list all servers rows: %w", err)
	}
	if err := r.loadTransports(ctx, servers); err != nil {
		return nil, err
	}
	return servers, nil
}

// ListCandidates returns only modeled, capacity-eligible placements for the
// requested transport. Legacy rollout exceptions and servers without an
// explicit public probe endpoint never enter the client failover contract.
func (r *ServerRepo) ListCandidates(ctx context.Context, protocol string, freshness time.Duration) ([]models.ServerCandidate, error) {
	if strings.TrimSpace(protocol) == "" || freshness <= 0 {
		return nil, errors.New("protocol and positive freshness are required")
	}
	rows, err := r.pool.Query(ctx, `
		SELECT server.id, server.name, server.location, server.country_code,
		       transport.protocol, server.probe_url, transport.endpoint,
		       transport.port, transport.priority
		FROM vpn_servers server
		JOIN vpn_server_transports transport
		  ON transport.server_id = server.id AND transport.protocol = $1
		WHERE server.legacy_node_unbound = FALSE
		  AND server.is_active = TRUE
		  AND server.draining_at IS NULL
		  AND server.probe_url <> ''
		  AND transport.enabled = TRUE
		  AND transport.health_status = 'healthy'
		  AND vpn_server_placement_eligible(server.id, $1, $2::interval, TRUE)
		ORDER BY transport.priority DESC,
		         (server.current_peers::float / GREATEST(server.max_peers, 1)) ASC,
		         lower(server.name), server.id`, protocol, freshness.String())
	if err != nil {
		return nil, fmt.Errorf("list server candidates: %w", err)
	}
	defer rows.Close()

	candidates := make([]models.ServerCandidate, 0)
	for rows.Next() {
		var candidate models.ServerCandidate
		if err := rows.Scan(
			&candidate.ID, &candidate.Name, &candidate.Location, &candidate.CountryCode,
			&candidate.Protocol, &candidate.ProbeURL, &candidate.Endpoint,
			&candidate.Port, &candidate.Priority,
		); err != nil {
			return nil, fmt.Errorf("scan server candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list server candidate rows: %w", err)
	}
	return candidates, nil
}

func (r *ServerRepo) ListAdminPage(ctx context.Context, options ListOptions) ([]models.VPNServer, int, error) {
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if options.Search != "" {
		args = append(args, strings.ToLower(options.Search)+"%")
		placeholder := fmt.Sprintf("$%d", len(args))
		clauses = append(clauses, fmt.Sprintf(
			"(lower(name) LIKE %s OR lower(host) LIKE %s OR lower(location) LIKE %s OR lower(country_code) LIKE %s)",
			placeholder, placeholder, placeholder, placeholder,
		))
	}
	switch options.Status {
	case "active":
		clauses = append(clauses, "is_active = TRUE AND draining_at IS NULL")
	case "inactive":
		clauses = append(clauses, "is_active = FALSE AND draining_at IS NULL")
	case "draining":
		clauses = append(clauses, "draining_at IS NOT NULL")
	}
	where := listWhere(clauses)
	direction := listDirection(options.Order)
	orderBy := "lower(name) " + direction + ", id " + direction
	switch options.Sort {
	case "created_at":
		orderBy = "created_at " + direction + ", id " + direction
	case "current_peers":
		orderBy = "current_peers " + direction + ", id " + direction
	}
	limitPlaceholder := fmt.Sprintf("$%d", len(args)+1)
	offsetPlaceholder := fmt.Sprintf("$%d", len(args)+2)
	countSQL := "SELECT COUNT(*) FROM vpn_servers" + where
	listSQL := "SELECT " + serverColumns + " FROM vpn_servers" + where +
		" ORDER BY " + orderBy + " LIMIT " + limitPlaceholder + " OFFSET " + offsetPlaceholder
	servers, total, err := queryPage(ctx, r.pool, countSQL, listSQL, args, options.Limit, options.Offset,
		func(rows pgx.Rows) (models.VPNServer, error) {
			server, err := scanServer(rows)
			if err != nil {
				return models.VPNServer{}, fmt.Errorf("scan admin server: %w", err)
			}
			return *server, nil
		})
	if err != nil {
		return nil, 0, fmt.Errorf("list admin servers: %w", err)
	}
	if err := r.loadTransports(ctx, servers); err != nil {
		return nil, 0, err
	}
	return servers, total, nil
}

// ListForReconciliation includes active servers and inactive servers that
// still carry durable peer intent. A newly staged inactive server with no
// sessions is deliberately not probed or reported as an observation failure.
func (r *ServerRepo) ListForReconciliation(ctx context.Context) ([]models.VPNServer, error) {
	query := `SELECT ` + serverColumns + `
		FROM vpn_servers server
		WHERE server.is_active = TRUE
		   OR server.current_peers > 0
		   OR EXISTS (
			SELECT 1 FROM peers peer
			WHERE peer.server_id = server.id AND peer.is_active = TRUE
		   )
		   OR EXISTS (
			SELECT 1 FROM peer_operations operation
			WHERE operation.server_id = server.id
			  AND operation.state IN ('pending', 'core_applied', 'cleanup_pending')
		   )
		   OR EXISTS (
			SELECT 1
			FROM peer_operations operation
			JOIN peers previous ON previous.id = operation.previous_peer_id
			WHERE previous.server_id = server.id
			  AND operation.state = 'cleanup_pending'
		   )
		ORDER BY server.name`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list servers for reconciliation: %w", err)
	}
	defer rows.Close()
	servers := make([]models.VPNServer, 0)
	for rows.Next() {
		server, err := scanServer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan server for reconciliation: %w", err)
		}
		servers = append(servers, *server)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list servers for reconciliation rows: %w", err)
	}
	return servers, nil
}

func (r *ServerRepo) LeastLoaded(ctx context.Context) (*models.VPNServer, error) {
	query := `
		SELECT ` + serverColumns + `
		FROM vpn_servers
		WHERE vpn_server_placement_eligible(id, 'wireguard', $1::interval, TRUE)
		ORDER BY (current_peers::float / GREATEST(max_peers, 1)) ASC
		LIMIT 1
	`
	s, err := scanServer(r.pool.QueryRow(ctx, query, DefaultNodeFreshness.String()))
	if err != nil {
		return nil, fmt.Errorf("no available server: %w", err)
	}
	servers := []models.VPNServer{*s}
	if err := r.loadTransports(ctx, servers); err != nil {
		return nil, err
	}
	*s = servers[0]
	return s, nil
}

func (r *ServerRepo) Update(ctx context.Context, s *models.VPNServer) error {
	defer r.InvalidateCache()
	query := `
		UPDATE vpn_servers
		SET name = $1, host = $2, probe_url = $3, endpoint = $4, port = $5, wg_port = $6, public_key = $7,
		    location = $8, country_code = $9, max_peers = $10, is_active = $11,
		    draining_at = $12, updated_at = NOW()
		WHERE id = $13
	`
	_, err := r.pool.Exec(ctx, query,
		s.Name, s.Host, s.ProbeURL, s.Endpoint, s.Port, s.WGPort, s.PublicKey, s.Location,
		s.CountryCode, s.MaxPeers, s.IsActive, s.DrainingAt, s.ID,
	)
	return err
}

// UpdateWithTransports updates the server and, when requested, replaces its
// transport contract in the same transaction.
func (r *ServerRepo) UpdateWithTransports(ctx context.Context, s *models.VPNServer, transports []models.TransportCapability, replace bool) error {
	if replace && len(transports) == 0 {
		return errors.New("server must have at least one transport")
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin update server: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE vpn_servers
		SET name = $1, host = $2, probe_url = $3, endpoint = $4, port = $5, wg_port = $6, public_key = $7,
		    location = $8, country_code = $9, max_peers = $10, is_active = $11,
		    draining_at = $12, updated_at = NOW()
		WHERE id = $13`,
		s.Name, s.Host, s.ProbeURL, s.Endpoint, s.Port, s.WGPort, s.PublicKey, s.Location,
		s.CountryCode, s.MaxPeers, s.IsActive, s.DrainingAt, s.ID)
	if err != nil {
		return fmt.Errorf("update server: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if replace {
		if err := replaceTransportsTx(ctx, tx, s.ID, transports); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit server update: %w", err)
	}
	r.InvalidateCache()
	return nil
}

// ReplaceTransports atomically replaces a server's advertised transport
// contract. Health state is intentionally initialized by the caller; it is
// later maintained by the gateway health checker.
func (r *ServerRepo) ReplaceTransports(ctx context.Context, serverID uuid.UUID, transports []models.TransportCapability) error {
	if len(transports) == 0 {
		return fmt.Errorf("server must have at least one transport")
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin replace server transports: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := replaceTransportsTx(ctx, tx, serverID, transports); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit server transports: %w", err)
	}
	r.InvalidateCache()
	return nil
}

func replaceTransportsTx(ctx context.Context, tx pgx.Tx, serverID uuid.UUID, transports []models.TransportCapability) error {
	if _, err := tx.Exec(ctx, `DELETE FROM vpn_server_transports WHERE server_id = $1`, serverID); err != nil {
		return fmt.Errorf("delete server transports: %w", err)
	}
	batch := &pgx.Batch{}
	for _, transport := range transports {
		metadata := []byte("{}")
		if len(transport.Metadata) > 0 {
			encoded, err := json.Marshal(transport.Metadata)
			if err != nil {
				return fmt.Errorf("encode transport metadata: %w", err)
			}
			metadata = encoded
		}
		batch.Queue(`
			INSERT INTO vpn_server_transports
				(server_id, protocol, endpoint, port, enabled, priority, health_status, metadata, last_checked_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			serverID, transport.Protocol, transport.Host, transport.Port, transport.Enabled,
			transport.Priority, transport.HealthStatus, metadata, transport.LastChecked)
	}
	results := tx.SendBatch(ctx, batch)
	if err := results.Close(); err != nil {
		return fmt.Errorf("insert server transports: %w", err)
	}
	return nil
}

// UpdateTransportHealth stores the last outcome of a gateway health probe.
func (r *ServerRepo) UpdateTransportHealth(ctx context.Context, serverID uuid.UUID, protocol, status string, checkedAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE vpn_server_transports
		SET health_status = $3, last_checked_at = $4, updated_at = NOW()
		WHERE server_id = $1 AND protocol = $2`, serverID, protocol, status, checkedAt)
	if err == nil {
		r.InvalidateCache()
	}
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

// DrainAndDelete first makes the server unavailable for new connections. The
// draining marker is committed even when active sessions or live operations
// keep the server from being deleted.
func (r *ServerRepo) DrainAndDelete(ctx context.Context, id uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin server drain: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	operationRows, err := tx.Query(ctx, `
		SELECT operation.id
		FROM peer_operations operation
		LEFT JOIN peers previous ON previous.id = operation.previous_peer_id
		WHERE operation.state IN ('pending', 'core_applied', 'cleanup_pending')
		  AND (operation.server_id = $1 OR previous.server_id = $1)
		ORDER BY operation.id
		FOR UPDATE OF operation`, id)
	if err != nil {
		return fmt.Errorf("lock server operations: %w", err)
	}
	for operationRows.Next() {
		var operationID uuid.UUID
		if err := operationRows.Scan(&operationID); err != nil {
			operationRows.Close()
			return fmt.Errorf("scan locked server operation: %w", err)
		}
	}
	if err := operationRows.Err(); err != nil {
		operationRows.Close()
		return fmt.Errorf("lock server operation rows: %w", err)
	}
	operationRows.Close()

	peerRows, err := tx.Query(ctx, `
		SELECT id FROM peers
		WHERE server_id = $1 AND is_active = TRUE
		ORDER BY id FOR UPDATE`, id)
	if err != nil {
		return fmt.Errorf("lock server sessions: %w", err)
	}
	for peerRows.Next() {
		var peerID uuid.UUID
		if err := peerRows.Scan(&peerID); err != nil {
			peerRows.Close()
			return fmt.Errorf("scan locked server session: %w", err)
		}
	}
	if err := peerRows.Err(); err != nil {
		peerRows.Close()
		return fmt.Errorf("lock server session rows: %w", err)
	}
	peerRows.Close()

	var serverID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM vpn_servers WHERE id = $1 FOR UPDATE`, id).Scan(&serverID); err != nil {
		return fmt.Errorf("lock draining server: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE vpn_servers
		SET is_active = FALSE, draining_at = COALESCE(draining_at, NOW()), updated_at = NOW()
		WHERE id = $1`, id); err != nil {
		return fmt.Errorf("mark server draining: %w", err)
	}

	var blockers int
	if err := tx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM peers WHERE server_id = $1 AND is_active = TRUE) +
			(SELECT COUNT(*)
			 FROM peer_operations operation
			 LEFT JOIN peers previous ON previous.id = operation.previous_peer_id
			 WHERE operation.state IN ('pending', 'core_applied', 'cleanup_pending')
			   AND (operation.server_id = $1 OR previous.server_id = $1))`, id).Scan(&blockers); err != nil {
		return fmt.Errorf("count server drain blockers: %w", err)
	}
	if blockers > 0 {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit server draining state: %w", err)
		}
		r.InvalidateCache()
		return ErrServerNotDrained
	}
	if _, err := tx.Exec(ctx, `DELETE FROM vpn_servers WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete drained server: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit server deletion: %w", err)
	}
	r.InvalidateCache()
	return nil
}

// loadTransports attaches the normalized transport contract in a single query.
func (r *ServerRepo) loadTransports(ctx context.Context, servers []models.VPNServer) error {
	if len(servers) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, len(servers))
	byID := make(map[uuid.UUID]*models.VPNServer, len(servers))
	for i := range servers {
		ids[i] = servers[i].ID
		servers[i].SetTransports(nil)
		byID[servers[i].ID] = &servers[i]
	}

	rows, err := r.pool.Query(ctx, `
		SELECT server_id, protocol, endpoint, port, enabled, priority, health_status, metadata, last_checked_at
		FROM vpn_server_transports
		WHERE server_id = ANY($1)
		ORDER BY server_id, priority DESC, protocol`, ids)
	if err != nil {
		return fmt.Errorf("list server transports: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var serverID uuid.UUID
		var capability models.TransportCapability
		var metadata []byte
		if err := rows.Scan(&serverID, &capability.Protocol, &capability.Host, &capability.Port,
			&capability.Enabled, &capability.Priority, &capability.HealthStatus, &metadata, &capability.LastChecked); err != nil {
			return fmt.Errorf("scan server transport: %w", err)
		}
		capability.Host = normalizeStoredTransportHost(capability.Host, capability.Port)
		if len(metadata) > 0 && string(metadata) != "{}" {
			if err := json.Unmarshal(metadata, &capability.Metadata); err != nil {
				return fmt.Errorf("decode server transport metadata: %w", err)
			}
		}
		if server := byID[serverID]; server != nil {
			server.Transports = append(server.Transports, capability)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate server transports: %w", err)
	}
	for i := range servers {
		servers[i].ApplyCapabilities()
	}
	return nil
}

// normalizeStoredTransportHost repairs rows created by migration 7, where an
// endpoint could contain the same port that was also stored in the port column.
func normalizeStoredTransportHost(host string, port int) string {
	host = strings.TrimSpace(host)
	parsedHost, parsedPort, err := net.SplitHostPort(host)
	if err == nil && parsedPort == strconv.Itoa(port) {
		return parsedHost
	}
	return host
}

func scanServer(row rowScanner) (*models.VPNServer, error) {
	var s models.VPNServer
	if err := row.Scan(
		&s.ID, &s.NodeID, &s.LegacyNodeUnbound, &s.Name, &s.Host, &s.ProbeURL, &s.Endpoint, &s.Port, &s.WGPort, &s.PublicKey,
		&s.Location, &s.CountryCode, &s.MaxPeers, &s.CurrentPeers, &s.IsActive,
		&s.DrainingAt, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	s.ApplyCapabilities()
	return &s, nil
}
