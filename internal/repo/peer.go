package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/models"
)

type PeerRepo struct {
	pool   *pgxpool.Pool
	cipher *dataencryption.Cipher
}

func NewPeerRepo(pool *pgxpool.Pool, cipher ...*dataencryption.Cipher) *PeerRepo {
	var dataCipher *dataencryption.Cipher
	if len(cipher) > 0 {
		dataCipher = cipher[0]
	}
	return &PeerRepo{pool: pool, cipher: dataCipher}
}

func (r *PeerRepo) Create(ctx context.Context, p *models.Peer) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	ciphertext, version, err := sealStoredPresharedKey(r.cipher, dataencryption.PeerPresharedKey, p.ID, p.PresharedKey)
	if err != nil {
		return fmt.Errorf("protect peer PSK: %w", err)
	}
	query := `
		INSERT INTO peers (
			id, user_id, server_id, public_key, preshared_key,
			preshared_key_ciphertext, preshared_key_version,
			assigned_ip, device_name, device_id
		) VALUES ($1, $2, $3, $4, '', $5, $6, $7, $8, $9)
		RETURNING is_active, created_at
	`
	return r.pool.QueryRow(ctx, query,
		p.ID, p.UserID, p.ServerID, p.PublicKey, ciphertext,
		nullableEncryptionVersion(version), p.AssignedIP, p.DeviceName, p.DeviceID,
	).Scan(&p.IsActive, &p.CreatedAt)
}

func (r *PeerRepo) DeactivateByDeviceID(ctx context.Context, userID, deviceID uuid.UUID) error {
	query := `UPDATE peers SET is_active = FALSE, preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL WHERE user_id = $1 AND device_id = $2 AND is_active = TRUE`
	_, err := r.pool.Exec(ctx, query, userID, deviceID)
	return err
}

func (r *PeerRepo) DeactivateByPublicKey(ctx context.Context, userID uuid.UUID, publicKey string) error {
	query := `UPDATE peers SET is_active = FALSE, preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL WHERE user_id = $1 AND public_key = $2 AND is_active = TRUE`
	_, err := r.pool.Exec(ctx, query, userID, publicKey)
	return err
}

func (r *PeerRepo) DeactivateByServerAndIP(ctx context.Context, serverID uuid.UUID, assignedIP string) error {
	query := `UPDATE peers SET is_active = FALSE, preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL WHERE server_id = $1 AND assigned_ip = $2 AND is_active = TRUE`
	_, err := r.pool.Exec(ctx, query, serverID, assignedIP)
	return err
}

func (r *PeerRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
		       provision_operation_id, last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers WHERE id = $1
	`
	p, err := scanOperationPeer(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("get peer: %w", err)
	}
	return p, nil
}

// GetByIDForPresharedKeyExport authorizes the owner (or an explicitly
// privileged administrator) in PostgreSQL before recoverable key material is
// loaded and decrypted. Ordinary peer reads never load it.
func (r *PeerRepo) GetByIDForPresharedKeyExport(ctx context.Context, id, requesterID uuid.UUID, allowAnyUser bool) (*models.Peer, error) {
	var peer models.Peer
	var legacyPresharedKey string
	var ciphertext []byte
	var version int16
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, server_id, public_key, preshared_key,
		       preshared_key_ciphertext, COALESCE(preshared_key_version, 0),
		       assigned_ip, is_active, device_name, device_id,
		       provision_operation_id, last_handshake, bytes_sent, bytes_received,
		       created_at, expires_at
		FROM peers
		WHERE id = $1 AND (user_id = $2 OR $3)`, id, requesterID, allowAnyUser).Scan(
		&peer.ID, &peer.UserID, &peer.ServerID, &peer.PublicKey,
		&legacyPresharedKey, &ciphertext, &version, &peer.AssignedIP,
		&peer.IsActive, &peer.DeviceName, &peer.DeviceID,
		&peer.ProvisionOperationID, &peer.LastHandshake, &peer.BytesSent,
		&peer.BytesReceived, &peer.CreatedAt, &peer.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get peer for authorized export: %w", err)
	}
	peer.PresharedKey, err = openStoredPresharedKey(r.cipher, dataencryption.PeerPresharedKey, peer.ID, legacyPresharedKey, ciphertext, version)
	if err != nil {
		return nil, fmt.Errorf("open peer PSK for authorized export: %w", err)
	}
	return &peer, nil
}

func (r *PeerRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
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
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.PresharedKey, &p.AssignedIP, &p.IsActive, &p.DeviceName, &p.DeviceID,
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

func (r *PeerRepo) ListActiveByUser(ctx context.Context, userID uuid.UUID) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers
		WHERE user_id = $1 AND is_active = TRUE
		ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list active peers by user: %w", err)
	}
	defer rows.Close()

	peers := make([]models.Peer, 0)
	for rows.Next() {
		peer, err := scanPeer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan active peer by user: %w", err)
		}
		peers = append(peers, *peer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active peers by user rows: %w", err)
	}
	return peers, nil
}

// ListActiveWithDeniedAccess returns sessions that must be removed because
// their user was banned or their owning device was revoked. These durable
// flags also cover a connection that completed concurrently with the action.
func (r *PeerRepo) ListActiveWithDeniedAccess(ctx context.Context) ([]models.Peer, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT peer.id, peer.user_id, peer.server_id, peer.public_key,
		       ''::text, peer.assigned_ip, peer.is_active, peer.device_name,
		       peer.device_id, peer.provision_operation_id, peer.last_handshake,
		       peer.bytes_sent, peer.bytes_received, peer.created_at, peer.expires_at
		FROM peers peer
		JOIN users ON users.id = peer.user_id
		JOIN devices ON devices.id = peer.device_id
		WHERE peer.is_active = TRUE
		  AND (users.is_banned = TRUE OR devices.revoked_at IS NOT NULL)
		ORDER BY peer.created_at, peer.id`)
	if err != nil {
		return nil, fmt.Errorf("list active peers with denied access: %w", err)
	}
	defer rows.Close()
	peers := make([]models.Peer, 0)
	for rows.Next() {
		peer, err := scanOperationPeer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan active peer with denied access: %w", err)
		}
		peers = append(peers, *peer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active peers with denied access rows: %w", err)
	}
	return peers, nil
}

func (r *PeerRepo) ListByDevice(ctx context.Context, userID, deviceID uuid.UUID, limit, offset int) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers
		WHERE user_id = $1 AND device_id = $2
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := r.pool.Query(ctx, query, userID, deviceID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list device sessions: %w", err)
	}
	defer rows.Close()

	peers := make([]models.Peer, 0)
	for rows.Next() {
		peer, err := scanPeer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan device session: %w", err)
		}
		peers = append(peers, *peer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list device sessions rows: %w", err)
	}
	return peers, nil
}

func (r *PeerRepo) CountByDevice(ctx context.Context, userID, deviceID uuid.UUID) (int, error) {
	var count int
	if err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM peers WHERE user_id = $1 AND device_id = $2`, userID, deviceID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count device sessions: %w", err)
	}
	return count, nil
}

func (r *PeerRepo) GetActiveByDevice(ctx context.Context, userID, deviceID uuid.UUID) (*models.Peer, error) {
	peer, err := scanPeer(r.pool.QueryRow(ctx, `
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers
		WHERE user_id = $1 AND device_id = $2 AND is_active = TRUE`, userID, deviceID))
	if err != nil {
		return nil, fmt.Errorf("get active device peer: %w", err)
	}
	return peer, nil
}

func scanPeer(row interface{ Scan(...interface{}) error }) (*models.Peer, error) {
	var peer models.Peer
	if err := row.Scan(
		&peer.ID, &peer.UserID, &peer.ServerID, &peer.PublicKey, &peer.PresharedKey,
		&peer.AssignedIP, &peer.IsActive, &peer.DeviceName, &peer.DeviceID,
		&peer.LastHandshake, &peer.BytesSent, &peer.BytesReceived, &peer.CreatedAt, &peer.ExpiresAt,
	); err != nil {
		return nil, err
	}
	return &peer, nil
}

func (r *PeerRepo) ListByServer(ctx context.Context, serverID uuid.UUID) ([]models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
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
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.PresharedKey, &p.AssignedIP, &p.IsActive, &p.DeviceName, &p.DeviceID,
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
		SELECT p.id, p.user_id, COALESCE(u.email, ''), p.server_id, p.public_key, ''::text, p.assigned_ip,
		       p.is_active, p.device_name, p.device_id, p.last_handshake, p.bytes_sent, p.bytes_received,
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
			&p.ID, &p.UserID, &p.UserEmail, &p.ServerID, &p.PublicKey, &p.PresharedKey, &p.AssignedIP, &p.IsActive, &p.DeviceName, &p.DeviceID,
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
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
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
			&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.PresharedKey, &p.AssignedIP, &p.IsActive, &p.DeviceName, &p.DeviceID,
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
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
		       provision_operation_id, last_handshake, bytes_sent, bytes_received, created_at, expires_at
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
		peer, err := scanOperationPeer(rows)
		if err != nil {
			return nil, err
		}
		peers = append(peers, *peer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list stale peers rows: %w", err)
	}
	return peers, nil
}

// DeactivateAndRecount retires a confirmed-absent peer and repairs the logical
// capacity counter under the same server lock used by reconciliation.
func (r *PeerRepo) DeactivateAndRecount(ctx context.Context, peerID uuid.UUID) (bool, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin peer retirement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var serverID uuid.UUID
	var active bool
	if err := tx.QueryRow(ctx, `SELECT server_id, is_active FROM peers WHERE id = $1 FOR UPDATE`, peerID).Scan(&serverID, &active); err != nil {
		return false, fmt.Errorf("lock retiring peer: %w", err)
	}
	var lockedServerID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM vpn_servers WHERE id = $1 FOR UPDATE`, serverID).Scan(&lockedServerID); err != nil {
		return false, fmt.Errorf("lock retiring peer server: %w", err)
	}
	if active {
		if _, err := tx.Exec(ctx, `UPDATE peers SET is_active = FALSE, preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL WHERE id = $1`, peerID); err != nil {
			return false, fmt.Errorf("retire peer: %w", err)
		}
	}
	if _, err := recalculateServerPeerCount(ctx, tx, serverID); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit peer retirement: %w", err)
	}
	return active, nil
}

func (r *PeerRepo) UpdateStats(ctx context.Context, id uuid.UUID, bytesSent, bytesRecv int64, lastHandshake *time.Time) error {
	query := `UPDATE peers SET bytes_sent = $1, bytes_received = $2, last_handshake = $3 WHERE id = $4`
	_, err := r.pool.Exec(ctx, query, bytesSent, bytesRecv, lastHandshake, id)
	return err
}

func (r *PeerRepo) Deactivate(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE peers SET is_active = FALSE, preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL WHERE id = $1`, id)
	return err
}

type PeerObservation struct {
	PublicKey     string
	OperationID   string
	LastHandshake *time.Time
	BytesSent     int64
	BytesReceived int64
}

type ServerReconciliation struct {
	ActivePeers      []models.Peer
	DeactivatedPeers int
	CurrentPeers     int
}

// ReconcileServer applies one valid Core observation. Absence, stats,
// device last-seen and the logical capacity counter are committed atomically;
// callers must never invoke this method for a failed Core read.
func (r *PeerRepo) ReconcileServer(ctx context.Context, serverID uuid.UUID, observationStartedAt time.Time, observations []PeerObservation) (*ServerReconciliation, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin server reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT `+operationPeerColumns+`
		FROM peers
		WHERE server_id = $1 AND is_active = TRUE
		ORDER BY created_at, id
		FOR UPDATE`, serverID)
	if err != nil {
		return nil, fmt.Errorf("lock active server peers: %w", err)
	}
	active := make([]models.Peer, 0)
	for rows.Next() {
		peer, err := scanOperationPeer(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan active server peer: %w", err)
		}
		active = append(active, *peer)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("list active server peer rows: %w", err)
	}
	rows.Close()
	var lockedServerID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM vpn_servers WHERE id = $1 FOR UPDATE`, serverID).Scan(&lockedServerID); err != nil {
		return nil, fmt.Errorf("lock reconciled server: %w", err)
	}

	exact := make(map[string]PeerObservation, len(observations))
	byKey := make(map[string]PeerObservation, len(observations))
	for _, observation := range observations {
		exact[observation.PublicKey+"\x00"+observation.OperationID] = observation
		byKey[observation.PublicKey] = observation
	}

	result := &ServerReconciliation{ActivePeers: make([]models.Peer, 0, len(active))}
	for index := range active {
		peer := &active[index]
		var observation PeerObservation
		var present bool
		if peer.ProvisionOperationID != nil {
			observation, present = exact[peer.PublicKey+"\x00"+peer.ProvisionOperationID.String()]
		} else {
			// Legacy rows have no durable owner. Matching by key preserves them,
			// but all new rows require exact operation identity.
			observation, present = byKey[peer.PublicKey]
		}
		if !present {
			// A peer committed after the Core read began belongs to a concurrent
			// request and cannot be declared absent from this older snapshot.
			if !peer.CreatedAt.Before(observationStartedAt) {
				result.ActivePeers = append(result.ActivePeers, *peer)
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE peers SET is_active = FALSE, preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL WHERE id = $1`, peer.ID); err != nil {
				return nil, fmt.Errorf("deactivate absent server peer: %w", err)
			}
			result.DeactivatedPeers++
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE peers
			SET bytes_sent = $2, bytes_received = $3, last_handshake = $4
			WHERE id = $1`, peer.ID, observation.BytesSent, observation.BytesReceived,
			observation.LastHandshake); err != nil {
			return nil, fmt.Errorf("update reconciled peer stats: %w", err)
		}
		peer.BytesSent = observation.BytesSent
		peer.BytesReceived = observation.BytesReceived
		peer.LastHandshake = observation.LastHandshake
		if observation.LastHandshake != nil && peer.DeviceID != nil {
			if _, err := tx.Exec(ctx, `
				UPDATE devices
				SET last_seen_at = GREATEST(last_seen_at, $2)
				WHERE id = $1`, *peer.DeviceID, *observation.LastHandshake); err != nil {
				return nil, fmt.Errorf("update reconciled device last seen: %w", err)
			}
		}
		result.ActivePeers = append(result.ActivePeers, *peer)
	}

	currentPeers, err := recalculateServerPeerCount(ctx, tx, serverID)
	if err != nil {
		return nil, err
	}
	result.CurrentPeers = currentPeers
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit server reconciliation: %w", err)
	}
	return result, nil
}

func recalculateServerPeerCount(ctx context.Context, tx pgx.Tx, serverID uuid.UUID) (int, error) {
	var currentPeers int
	if err := tx.QueryRow(ctx, `
		WITH active AS (
			SELECT COUNT(*) AS count FROM peers
			WHERE server_id = $1 AND is_active = TRUE
		), reserved AS (
			SELECT COUNT(*) AS count
			FROM peer_operations operation
			WHERE operation.server_id = $1
			  AND operation.state IN ('pending', 'core_applied')
			  AND operation.capacity_reserved = TRUE
			  AND NOT EXISTS (
				SELECT 1 FROM peers peer
				WHERE peer.provision_operation_id = operation.id
				  AND peer.is_active = TRUE
			  )
		)
		UPDATE vpn_servers
		SET current_peers = active.count + reserved.count, updated_at = NOW()
		FROM active, reserved
		WHERE id = $1
		RETURNING current_peers`, serverID).Scan(&currentPeers); err != nil {
		return 0, fmt.Errorf("recalculate server peer count: %w", err)
	}
	return currentPeers, nil
}

func (r *PeerRepo) CountByUser(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM peers WHERE user_id = $1 AND is_active = TRUE`, userID).Scan(&count)
	return count, err
}

// GetActiveByUserAndPublicKey returns the active peer record for the given user
// and WireGuard public key, or (nil, pgx.ErrNoRows) if none exists.
// This is used for idempotent connect: if the client retries with the same key
// we return the existing allocation instead of counting it as a new device.
func (r *PeerRepo) GetActiveByUserAndPublicKey(ctx context.Context, userID uuid.UUID, publicKey string) (*models.Peer, error) {
	query := `
		SELECT id, user_id, server_id, public_key, ''::text, assigned_ip, is_active, device_name, device_id,
		       last_handshake, bytes_sent, bytes_received, created_at, expires_at
		FROM peers
		WHERE user_id = $1 AND public_key = $2 AND is_active = TRUE
		LIMIT 1
	`
	var p models.Peer
	err := r.pool.QueryRow(ctx, query, userID, publicKey).Scan(
		&p.ID, &p.UserID, &p.ServerID, &p.PublicKey, &p.PresharedKey, &p.AssignedIP, &p.IsActive, &p.DeviceName, &p.DeviceID,
		&p.LastHandshake, &p.BytesSent, &p.BytesReceived, &p.CreatedAt, &p.ExpiresAt,
	)
	if err != nil {
		return nil, err
	}
	return &p, nil
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
