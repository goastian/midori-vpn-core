package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/goastian/midori-vpn-core/internal/models"
)

var (
	ErrConnectionInProgress  = errors.New("connection operation is already in progress")
	ErrDeviceLimitReached    = errors.New("device limit reached")
	ErrServerCapacity        = errors.New("server is full or inactive")
	ErrServerPlacement       = errors.New("server node is not eligible for placement")
	ErrOperationState        = errors.New("peer operation is in an invalid state")
	ErrPeerOperationConflict = errors.New("public key belongs to another device")
	ErrAccessRevoked         = errors.New("user or device access is revoked")
)

type BeginConnectParams struct {
	OperationID      uuid.UUID
	UserID           uuid.UUID
	Device           *models.Device
	LegacyDeviceName string
	ServerID         uuid.UUID
	PublicKey        string
	PresharedKey     string
	PQKEMCiphertext  string
	MaxDevices       int
}

type BeginConnectResult struct {
	Operation    *models.PeerOperation
	Device       *models.Device
	PreviousPeer *models.Peer
	ExistingPeer *models.Peer
}

type BeginDisconnectResult struct {
	Operation        *models.PeerOperation
	Peer             *models.Peer
	AlreadyConverged bool
}

type PeerOperationRepo struct {
	pool   *pgxpool.Pool
	cipher *dataencryption.Cipher
}

type PendingCleanupTarget struct {
	ServerID    uuid.UUID
	PublicKey   string
	OperationID string
}

func NewPeerOperationRepo(pool *pgxpool.Pool, cipher ...*dataencryption.Cipher) *PeerOperationRepo {
	var dataCipher *dataencryption.Cipher
	if len(cipher) > 0 {
		dataCipher = cipher[0]
	}
	return &PeerOperationRepo{pool: pool, cipher: dataCipher}
}

const operationColumns = `id, action, state, user_id, device_id, server_id,
	public_key, preshared_key, preshared_key_ciphertext, COALESCE(preshared_key_version, 0),
	pq_kem_ciphertext, previous_peer_id,
	previous_operation_id, COALESCE(assigned_ip, ''), capacity_reserved, attempts, last_error,
	core_applied_at, completed_at, created_at, updated_at`

func (r *PeerOperationRepo) scanPeerOperation(row interface{ Scan(...interface{}) error }) (*models.PeerOperation, error) {
	var operation models.PeerOperation
	var legacyPresharedKey string
	var ciphertext []byte
	var version int16
	if err := row.Scan(
		&operation.ID, &operation.Action, &operation.State, &operation.UserID,
		&operation.DeviceID, &operation.ServerID, &operation.PublicKey,
		&legacyPresharedKey, &ciphertext, &version, &operation.PQKEMCiphertext,
		&operation.PreviousPeerID, &operation.PreviousOperationID, &operation.AssignedIP,
		&operation.CapacityReserved, &operation.Attempts,
		&operation.LastError, &operation.CoreAppliedAt, &operation.CompletedAt,
		&operation.CreatedAt, &operation.UpdatedAt,
	); err != nil {
		return nil, err
	}
	presharedKey, err := openStoredPresharedKey(r.cipher, dataencryption.PeerOperationPresharedKey, operation.ID, legacyPresharedKey, ciphertext, version)
	if err != nil {
		return nil, err
	}
	operation.PresharedKey = presharedKey
	return &operation, nil
}

const operationPeerColumns = `id, user_id, server_id, public_key,
	''::text, assigned_ip, is_active, device_name, device_id,
	provision_operation_id, last_handshake, bytes_sent, bytes_received,
	created_at, expires_at`

func scanOperationPeer(row interface{ Scan(...interface{}) error }) (*models.Peer, error) {
	var peer models.Peer
	if err := row.Scan(
		&peer.ID, &peer.UserID, &peer.ServerID, &peer.PublicKey,
		&peer.PresharedKey, &peer.AssignedIP, &peer.IsActive, &peer.DeviceName,
		&peer.DeviceID, &peer.ProvisionOperationID, &peer.LastHandshake,
		&peer.BytesSent, &peer.BytesReceived, &peer.CreatedAt, &peer.ExpiresAt,
	); err != nil {
		return nil, err
	}
	return &peer, nil
}

// FindCurrentByKey recognizes an in-flight request or a completed request that
// still owns the active peer. Historical completed operations do not block a
// later reuse after their peer has been retired.
func (r *PeerOperationRepo) FindCurrentByKey(ctx context.Context, userID uuid.UUID, publicKey string) (*models.PeerOperation, *models.Peer, error) {
	operation, err := r.scanPeerOperation(r.pool.QueryRow(ctx, `
		SELECT `+operationColumns+`
		FROM peer_operations operation
		WHERE operation.user_id = $1 AND operation.public_key = $2
		  AND (
		      operation.state IN ('pending', 'core_applied', 'cleanup_pending')
		      OR EXISTS (
		          SELECT 1 FROM peers peer
		          WHERE peer.provision_operation_id = operation.id
		            AND peer.is_active = TRUE
		      )
		  )
		ORDER BY operation.created_at DESC
		LIMIT 1`, userID, publicKey))
	if err != nil {
		return nil, nil, err
	}
	peer, peerErr := scanOperationPeer(r.pool.QueryRow(ctx, `
		SELECT `+operationPeerColumns+`
		FROM peers
		WHERE provision_operation_id = $1 AND is_active = TRUE`, operation.ID))
	if errors.Is(peerErr, pgx.ErrNoRows) {
		return operation, nil, nil
	}
	if peerErr != nil {
		return nil, nil, fmt.Errorf("load operation peer: %w", peerErr)
	}
	peer.PresharedKey = operation.PresharedKey
	return operation, peer, nil
}

// BeginConnect serializes a user's connection changes, locks the installation
// and absent public-key namespace, rechecks quota/capacity, then durably
// reserves the target server slot in the same transaction as the operation.
func (r *PeerOperationRepo) BeginConnect(ctx context.Context, params BeginConnectParams) (*BeginConnectResult, error) {
	if params.OperationID == uuid.Nil {
		return nil, errors.New("connection operation ID is required")
	}
	ciphertext, version, err := sealStoredPresharedKey(r.cipher, dataencryption.PeerOperationPresharedKey, params.OperationID, params.PresharedKey)
	if err != nil {
		return nil, fmt.Errorf("protect connection operation PSK: %w", err)
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin connection operation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var banned bool
	if err := tx.QueryRow(ctx, `SELECT is_banned FROM users WHERE id = $1 FOR UPDATE`, params.UserID).Scan(&banned); err != nil {
		return nil, fmt.Errorf("lock connection user: %w", err)
	}
	if banned {
		return nil, fmt.Errorf("user is banned")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, params.PublicKey); err != nil {
		return nil, fmt.Errorf("lock connection key: %w", err)
	}

	// Repeat the preflight idempotency lookup while holding both the user and
	// public-key locks. This closes the race where another request completes
	// between the handler's initial lookup and this transaction.
	existingPeer, existingErr := scanOperationPeer(tx.QueryRow(ctx, `
		SELECT `+operationPeerColumns+`
		FROM peers
		WHERE user_id = $1 AND public_key = $2 AND is_active = TRUE
		FOR UPDATE`, params.UserID, params.PublicKey))
	if existingErr == nil {
		if params.Device != nil && (existingPeer.DeviceID == nil || *existingPeer.DeviceID != params.Device.ID) {
			return nil, ErrPeerOperationConflict
		}
		var operation *models.PeerOperation
		if existingPeer.ProvisionOperationID != nil {
			operation, err = r.scanPeerOperation(tx.QueryRow(ctx, `
				SELECT `+operationColumns+` FROM peer_operations WHERE id = $1`, *existingPeer.ProvisionOperationID))
			if err != nil {
				return nil, fmt.Errorf("load existing connection operation: %w", err)
			}
			existingPeer.PresharedKey = operation.PresharedKey
		}
		return &BeginConnectResult{Operation: operation, Device: params.Device, ExistingPeer: existingPeer}, nil
	}
	if !errors.Is(existingErr, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check active connection key: %w", existingErr)
	}

	device := params.Device
	if device == nil {
		device, err = scanOperationDevice(tx.QueryRow(ctx, `
			INSERT INTO devices (user_id, reported_name, device_type)
			VALUES ($1, $2, 'manual')
			RETURNING id, user_id, client_instance_id, reported_name,
			          COALESCE(alias, ''), device_type,
			          COALESCE(adapter_reference, ''), first_seen_at,
			          last_seen_at, revoked_at`, params.UserID, params.LegacyDeviceName))
		if err != nil {
			return nil, fmt.Errorf("create connection device: %w", err)
		}
	} else {
		device, err = scanOperationDevice(tx.QueryRow(ctx, `
			SELECT id, user_id, client_instance_id, reported_name,
			       COALESCE(alias, ''), device_type,
			       COALESCE(adapter_reference, ''), first_seen_at,
			       last_seen_at, revoked_at
			FROM devices
			WHERE id = $1 AND user_id = $2
			FOR UPDATE`, device.ID, params.UserID))
		if err != nil {
			return nil, fmt.Errorf("lock connection device: %w", err)
		}
		if device.RevokedAt != nil {
			return nil, ErrDeviceRevoked
		}
	}

	var blockingID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id FROM peer_operations
		WHERE state IN ('pending', 'core_applied', 'cleanup_pending')
		  AND (device_id = $1 OR public_key = $2)
		LIMIT 1`, device.ID, params.PublicKey).Scan(&blockingID)
	if err == nil {
		return nil, ErrConnectionInProgress
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check concurrent connection operation: %w", err)
	}

	previousPeer, err := scanOperationPeer(tx.QueryRow(ctx, `
		SELECT `+operationPeerColumns+`
		FROM peers
		WHERE user_id = $1 AND device_id = $2 AND is_active = TRUE
		FOR UPDATE`, params.UserID, device.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		previousPeer = nil
	} else if err != nil {
		return nil, fmt.Errorf("lock previous device peer: %w", err)
	}

	var occupiedDevices int
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT device_id FROM peers
			WHERE user_id = $1 AND is_active = TRUE
			UNION
			SELECT device_id FROM peer_operations
			WHERE user_id = $1
			  AND state IN ('pending', 'core_applied', 'cleanup_pending')
		) occupied`, params.UserID).Scan(&occupiedDevices); err != nil {
		return nil, fmt.Errorf("recheck device quota: %w", err)
	}
	if previousPeer == nil && occupiedDevices >= params.MaxDevices {
		return nil, ErrDeviceLimitReached
	}

	capacityReserved := previousPeer == nil || previousPeer.ServerID != params.ServerID
	var active, placementEligible bool
	var currentPeers, maxPeers int
	if err := tx.QueryRow(ctx, `
		SELECT is_active, current_peers, max_peers,
		       vpn_server_placement_eligible(id, 'wireguard', $2::interval, $3)
		FROM vpn_servers WHERE id = $1 FOR UPDATE`, params.ServerID,
		DefaultNodeFreshness.String(), capacityReserved,
	).Scan(&active, &currentPeers, &maxPeers, &placementEligible); err != nil {
		return nil, fmt.Errorf("lock connection server: %w", err)
	}
	if !active || (capacityReserved && currentPeers >= maxPeers) {
		return nil, ErrServerCapacity
	}
	if !placementEligible {
		return nil, ErrServerPlacement
	}
	if capacityReserved {
		if _, err := tx.Exec(ctx, `
			UPDATE vpn_servers
			SET current_peers = current_peers + 1, updated_at = NOW()
			WHERE id = $1`, params.ServerID); err != nil {
			return nil, fmt.Errorf("reserve connection capacity: %w", err)
		}
	}

	action := models.PeerOperationConnect
	var previousPeerID *uuid.UUID
	var previousOperationID *uuid.UUID
	if previousPeer != nil {
		action = models.PeerOperationReplace
		previousPeerID = &previousPeer.ID
		previousOperationID = previousPeer.ProvisionOperationID
	}
	operation, err := r.scanPeerOperation(tx.QueryRow(ctx, `
		INSERT INTO peer_operations (
			id, action, state, user_id, device_id, server_id, public_key,
			preshared_key, preshared_key_ciphertext, preshared_key_version,
			pq_kem_ciphertext, previous_peer_id,
			previous_operation_id, capacity_reserved, attempts
		) VALUES ($1, $2, 'pending', $3, $4, $5, $6, '', $7, $8, $9, $10, $11, $12, 1)
		RETURNING `+operationColumns,
		params.OperationID, action, params.UserID, device.ID, params.ServerID,
		params.PublicKey, ciphertext, nullableEncryptionVersion(version), params.PQKEMCiphertext,
		previousPeerID, previousOperationID, capacityReserved))
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return nil, ErrConnectionInProgress
		}
		return nil, fmt.Errorf("create connection operation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit connection operation: %w", err)
	}
	return &BeginConnectResult{Operation: operation, Device: device, PreviousPeer: previousPeer}, nil
}

// BeginDisconnect durably records the exact database peer and Core operation
// that may be removed. Replays return the same live operation.
func (r *PeerOperationRepo) BeginDisconnect(ctx context.Context, peerID uuid.UUID) (*BeginDisconnectResult, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin disconnect operation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID uuid.UUID
	var publicKey string
	if err := tx.QueryRow(ctx, `
		SELECT user_id, public_key FROM peers WHERE id = $1`, peerID).Scan(&userID, &publicKey); err != nil {
		return nil, fmt.Errorf("load disconnect owner: %w", err)
	}
	var lockedUser uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&lockedUser); err != nil {
		return nil, fmt.Errorf("lock disconnect user: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, publicKey); err != nil {
		return nil, fmt.Errorf("lock disconnect key: %w", err)
	}

	peer, err := scanOperationPeer(tx.QueryRow(ctx, `
		SELECT `+operationPeerColumns+` FROM peers WHERE id = $1 FOR UPDATE`, peerID))
	if err != nil {
		return nil, fmt.Errorf("lock disconnect peer: %w", err)
	}
	if !peer.IsActive {
		return &BeginDisconnectResult{Peer: peer, AlreadyConverged: true}, nil
	}
	if peer.DeviceID == nil {
		return nil, errors.New("active peer has no device identity")
	}
	existing, err := r.scanPeerOperation(tx.QueryRow(ctx, `
		SELECT `+operationColumns+` FROM peer_operations
		WHERE action = 'disconnect' AND previous_peer_id = $1
		  AND state IN ('pending', 'core_applied', 'cleanup_pending')
		ORDER BY created_at DESC LIMIT 1`, peer.ID))
	if err == nil {
		return &BeginDisconnectResult{Operation: existing, Peer: peer}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("load existing disconnect operation: %w", err)
	}

	var blockingID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT id FROM peer_operations
		WHERE state IN ('pending', 'core_applied', 'cleanup_pending')
		  AND (device_id = $1 OR public_key = $2)
		LIMIT 1`, *peer.DeviceID, peer.PublicKey).Scan(&blockingID)
	if err == nil {
		return nil, ErrConnectionInProgress
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("check concurrent disconnect operation: %w", err)
	}

	operationID := uuid.New()
	operation, err := r.scanPeerOperation(tx.QueryRow(ctx, `
		INSERT INTO peer_operations (
			id, action, state, user_id, device_id, server_id, public_key,
			previous_peer_id, previous_operation_id, assigned_ip, attempts
		) VALUES ($1, 'disconnect', 'pending', $2, $3, $4, $5, $6, $7, $8, 0)
		RETURNING `+operationColumns,
		operationID, peer.UserID, *peer.DeviceID, peer.ServerID, peer.PublicKey,
		peer.ID, peer.ProvisionOperationID, peer.AssignedIP))
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return nil, ErrConnectionInProgress
		}
		return nil, fmt.Errorf("create disconnect operation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit disconnect operation: %w", err)
	}
	return &BeginDisconnectResult{Operation: operation, Peer: peer}, nil
}

func (r *PeerOperationRepo) SetPreviousOperationID(ctx context.Context, operationID, previousOperationID uuid.UUID) error {
	if previousOperationID == uuid.Nil {
		return errors.New("previous operation ID is required")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE peer_operations
		SET previous_operation_id = $2, updated_at = NOW()
		WHERE id = $1 AND state = 'pending' AND previous_peer_id IS NOT NULL`, operationID, previousOperationID)
	if err != nil {
		return fmt.Errorf("record previous Core operation: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrOperationState
	}
	return nil
}

func scanOperationDevice(row interface{ Scan(...interface{}) error }) (*models.Device, error) {
	var device models.Device
	if err := row.Scan(
		&device.ID, &device.UserID, &device.ClientInstanceID,
		&device.ReportedName, &device.Alias, &device.DeviceType,
		&device.AdapterReference, &device.FirstSeenAt, &device.LastSeenAt,
		&device.RevokedAt,
	); err != nil {
		return nil, err
	}
	if device.Alias != "" {
		device.DisplayName = device.Alias
	} else {
		device.DisplayName = device.ReportedName
	}
	return &device, nil
}

func (r *PeerOperationRepo) MarkCoreApplied(ctx context.Context, operationID uuid.UUID, assignedIP string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE peer_operations
		SET state = 'core_applied', assigned_ip = $2,
		    core_applied_at = COALESCE(core_applied_at, NOW()),
		    last_error = '', updated_at = NOW()
		WHERE id = $1 AND state IN ('pending', 'core_applied')`, operationID, assignedIP)
	if err != nil {
		return fmt.Errorf("mark Core operation applied: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrOperationState
	}
	return nil
}

// CompleteConnect creates the active peer and retires the prior database
// session atomically. Replacements remain cleanup_pending until the exact old
// Core owner has been confirmed absent, closing the crash window between the
// database commit and remote cleanup.
func (r *PeerOperationRepo) CompleteConnect(ctx context.Context, operationID uuid.UUID) (*models.Peer, *models.Peer, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("begin connection completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	operation, err := r.scanPeerOperation(tx.QueryRow(ctx, `
		SELECT `+operationColumns+` FROM peer_operations
		WHERE id = $1 FOR UPDATE`, operationID))
	if err != nil {
		return nil, nil, fmt.Errorf("lock connection operation: %w", err)
	}
	if operation.State == models.PeerOperationCompleted || operation.State == models.PeerOperationCleanupPending {
		peer, peerErr := scanOperationPeer(tx.QueryRow(ctx, `
			SELECT `+operationPeerColumns+` FROM peers
			WHERE provision_operation_id = $1 AND is_active = TRUE`, operationID))
		if peerErr == nil {
			peer.PresharedKey = operation.PresharedKey
		}
		return peer, nil, peerErr
	}
	if operation.State != models.PeerOperationCoreApplied {
		return nil, nil, ErrOperationState
	}
	var banned bool
	var revokedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT users.is_banned, devices.revoked_at
		FROM users JOIN devices ON devices.user_id = users.id
		WHERE users.id = $1 AND devices.id = $2
		FOR UPDATE OF users, devices`, operation.UserID, operation.DeviceID).Scan(&banned, &revokedAt); err != nil {
		return nil, nil, fmt.Errorf("lock operation access state: %w", err)
	}
	if banned || revokedAt != nil {
		return nil, nil, ErrAccessRevoked
	}

	var previousPeer *models.Peer
	if operation.PreviousPeerID != nil {
		previousPeer, err = scanOperationPeer(tx.QueryRow(ctx, `
			SELECT `+operationPeerColumns+` FROM peers
			WHERE id = $1 FOR UPDATE`, *operation.PreviousPeerID))
		if errors.Is(err, pgx.ErrNoRows) {
			previousPeer = nil
		} else if err != nil {
			return nil, nil, fmt.Errorf("lock replaced peer: %w", err)
		}
		if previousPeer != nil && previousPeer.IsActive {
			if _, err := tx.Exec(ctx, `
				UPDATE peers
				SET is_active = FALSE, preshared_key = '',
				    preshared_key_ciphertext = NULL, preshared_key_version = NULL
				WHERE id = $1`, previousPeer.ID); err != nil {
				return nil, nil, fmt.Errorf("retire previous peer: %w", err)
			}
			if previousPeer.ProvisionOperationID != nil {
				if _, err := tx.Exec(ctx, `
					UPDATE peer_operations
					SET preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL
					WHERE id = $1`, *previousPeer.ProvisionOperationID); err != nil {
					return nil, nil, fmt.Errorf("retire previous operation PSK: %w", err)
				}
			}
			if previousPeer.ServerID != operation.ServerID {
				if _, err := tx.Exec(ctx, `
					UPDATE vpn_servers
					SET current_peers = GREATEST(current_peers - 1, 0), updated_at = NOW()
					WHERE id = $1`, previousPeer.ServerID); err != nil {
					return nil, nil, fmt.Errorf("release previous server capacity: %w", err)
				}
			}
		}
	}

	var deviceName string
	if err := tx.QueryRow(ctx, `SELECT reported_name FROM devices WHERE id = $1`, operation.DeviceID).Scan(&deviceName); err != nil {
		return nil, nil, fmt.Errorf("load operation device name: %w", err)
	}
	peerID := uuid.New()
	peerCiphertext, peerVersion, err := sealStoredPresharedKey(r.cipher, dataencryption.PeerPresharedKey, peerID, operation.PresharedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("protect completed peer PSK: %w", err)
	}
	peer, err := scanOperationPeer(tx.QueryRow(ctx, `
		INSERT INTO peers (
			id, user_id, server_id, public_key, preshared_key,
			preshared_key_ciphertext, preshared_key_version, assigned_ip,
			device_name, device_id, provision_operation_id
		) VALUES ($1, $2, $3, $4, '', $5, $6, $7, $8, $9, $10)
		RETURNING `+operationPeerColumns,
		peerID, operation.UserID, operation.ServerID, operation.PublicKey,
		peerCiphertext, nullableEncryptionVersion(peerVersion), operation.AssignedIP,
		deviceName, operation.DeviceID, operation.ID))
	if err != nil {
		return nil, nil, fmt.Errorf("create completed peer: %w", err)
	}
	peer.PresharedKey = operation.PresharedKey
	if _, err := tx.Exec(ctx, `
		UPDATE peer_operations
		SET state = CASE WHEN previous_peer_id IS NULL THEN 'completed' ELSE 'cleanup_pending' END,
		    completed_at = NOW(), last_error = '',
		    updated_at = NOW()
		WHERE id = $1`, operation.ID); err != nil {
		return nil, nil, fmt.Errorf("complete peer operation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit completed peer operation: %w", err)
	}
	return peer, previousPeer, nil
}

// CompleteDisconnect atomically retires the exact target session, detaches it
// from meshes, repairs the server counter and closes the durable operation.
func (r *PeerOperationRepo) CompleteDisconnect(ctx context.Context, operationID uuid.UUID) (*models.Peer, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin disconnect completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	operation, err := r.scanPeerOperation(tx.QueryRow(ctx, `
		SELECT `+operationColumns+` FROM peer_operations WHERE id = $1 FOR UPDATE`, operationID))
	if err != nil {
		return nil, fmt.Errorf("lock disconnect operation: %w", err)
	}
	if operation.Action != models.PeerOperationDisconnect || operation.PreviousPeerID == nil {
		return nil, ErrOperationState
	}
	peer, err := scanOperationPeer(tx.QueryRow(ctx, `
		SELECT `+operationPeerColumns+` FROM peers WHERE id = $1 FOR UPDATE`, *operation.PreviousPeerID))
	if err != nil {
		return nil, fmt.Errorf("lock disconnect target: %w", err)
	}
	if operation.State == models.PeerOperationCompleted {
		return peer, nil
	}
	if operation.Action != models.PeerOperationDisconnect ||
		(operation.State != models.PeerOperationPending && operation.State != models.PeerOperationCoreApplied) {
		return nil, ErrOperationState
	}
	var lockedServer uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM vpn_servers WHERE id = $1 FOR UPDATE`, peer.ServerID).Scan(&lockedServer); err != nil {
		return nil, fmt.Errorf("lock disconnect server: %w", err)
	}
	if peer.IsActive {
		if _, err := tx.Exec(ctx, `
			UPDATE peers
			SET is_active = FALSE, preshared_key = '',
			    preshared_key_ciphertext = NULL, preshared_key_version = NULL
			WHERE id = $1`, peer.ID); err != nil {
			return nil, fmt.Errorf("deactivate disconnected peer: %w", err)
		}
		peer.IsActive = false
		peer.PresharedKey = ""
	}
	if peer.ProvisionOperationID != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE peer_operations
			SET preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL
			WHERE id = $1`, *peer.ProvisionOperationID); err != nil {
			return nil, fmt.Errorf("retire disconnected operation PSK: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh_members SET peer_id = NULL WHERE peer_id = $1`, peer.ID); err != nil {
		return nil, fmt.Errorf("detach disconnected peer from meshes: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE peer_operations
		SET state = 'completed', capacity_reserved = FALSE,
		    core_applied_at = COALESCE(core_applied_at, NOW()),
		    completed_at = COALESCE(completed_at, NOW()), last_error = '', updated_at = NOW()
		WHERE id = $1`, operation.ID); err != nil {
		return nil, fmt.Errorf("complete disconnect operation: %w", err)
	}
	if _, err := recalculateServerPeerCount(ctx, tx, peer.ServerID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit disconnect completion: %w", err)
	}
	return peer, nil
}

// AccessAllowed reports whether a live provisioning operation may still
// create a session after a concurrent ban or device revocation.
func (r *PeerOperationRepo) AccessAllowed(ctx context.Context, operationID uuid.UUID) (bool, error) {
	var allowed bool
	if err := r.pool.QueryRow(ctx, `
		SELECT NOT users.is_banned AND devices.revoked_at IS NULL
		FROM peer_operations operation
		JOIN users ON users.id = operation.user_id
		JOIN devices ON devices.id = operation.device_id
		WHERE operation.id = $1`, operationID).Scan(&allowed); err != nil {
		return false, fmt.Errorf("load operation access state: %w", err)
	}
	return allowed, nil
}

// CancelDeniedConnect closes a provisioning operation only after its exact
// Core owner is absent. It also releases any reserved capacity.
func (r *PeerOperationRepo) CancelDeniedConnect(ctx context.Context, operationID uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin denied connection cancellation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	operation, err := r.scanPeerOperation(tx.QueryRow(ctx, `
		SELECT `+operationColumns+` FROM peer_operations WHERE id = $1 FOR UPDATE`, operationID))
	if err != nil {
		return fmt.Errorf("lock denied connection operation: %w", err)
	}
	if operation.Action == models.PeerOperationDisconnect ||
		(operation.State != models.PeerOperationPending && operation.State != models.PeerOperationCoreApplied) {
		return ErrOperationState
	}
	if _, err := tx.Exec(ctx, `
		UPDATE peers
		SET is_active = FALSE, preshared_key = '',
		    preshared_key_ciphertext = NULL, preshared_key_version = NULL
		WHERE provision_operation_id = $1 AND is_active = TRUE`, operation.ID); err != nil {
		return fmt.Errorf("retire denied connection peer: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE peer_operations
		SET state = 'failed', capacity_reserved = FALSE,
		    preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL,
		    last_error = 'access revoked before completion', updated_at = NOW()
		WHERE id = $1`, operation.ID); err != nil {
		return fmt.Errorf("cancel denied connection operation: %w", err)
	}
	var lockedServer uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM vpn_servers WHERE id = $1 FOR UPDATE`, operation.ServerID).Scan(&lockedServer); err != nil {
		return fmt.Errorf("lock denied connection server: %w", err)
	}
	if _, err := recalculateServerPeerCount(ctx, tx, operation.ServerID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit denied connection cancellation: %w", err)
	}
	return nil
}

func (r *PeerOperationRepo) FailDefinitively(ctx context.Context, operationID uuid.UUID, cause error) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	operation, err := r.scanPeerOperation(tx.QueryRow(ctx, `
		SELECT `+operationColumns+` FROM peer_operations WHERE id = $1 FOR UPDATE`, operationID))
	if err != nil {
		return err
	}
	if operation.State != models.PeerOperationPending {
		return ErrOperationState
	}
	if operation.CapacityReserved {
		if _, err := tx.Exec(ctx, `
			UPDATE vpn_servers SET current_peers = GREATEST(current_peers - 1, 0), updated_at = NOW()
			WHERE id = $1`, operation.ServerID); err != nil {
			return err
		}
	}
	message := boundedOperationError(cause)
	if _, err := tx.Exec(ctx, `
		UPDATE peer_operations
		SET state = 'failed', capacity_reserved = FALSE,
		    preshared_key = '', preshared_key_ciphertext = NULL, preshared_key_version = NULL,
		    last_error = $2, updated_at = NOW()
		WHERE id = $1`, operationID, message); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PeerOperationRepo) MarkCleanupPending(ctx context.Context, operationID uuid.UUID, cause error) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE peer_operations
		SET state = 'cleanup_pending', last_error = $2, updated_at = NOW()
		WHERE id = $1 AND state IN ('completed', 'cleanup_pending')`, operationID, boundedOperationError(cause))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrOperationState
	}
	return nil
}

// ListLiveByServer returns every operation that can still own Core state. It is
// intentionally not limited to stale operations because the reconciler must
// protect fresh in-flight work while classifying Core peers as orphans.
func (r *PeerOperationRepo) ListLiveByServer(ctx context.Context, serverID uuid.UUID) ([]models.PeerOperation, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+operationColumns+`
		FROM peer_operations
		WHERE server_id = $1
		  AND state IN ('pending', 'core_applied', 'cleanup_pending')
		ORDER BY created_at, id`, serverID)
	if err != nil {
		return nil, fmt.Errorf("list live peer operations: %w", err)
	}
	defer rows.Close()

	operations := make([]models.PeerOperation, 0)
	for rows.Next() {
		operation, err := r.scanPeerOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("scan live peer operation: %w", err)
		}
		operations = append(operations, *operation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list live peer operations rows: %w", err)
	}
	return operations, nil
}

func (r *PeerOperationRepo) ListStaleLive(ctx context.Context, staleAfter time.Duration) ([]models.PeerOperation, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+operationColumns+`
		FROM peer_operations
		WHERE state IN ('pending', 'core_applied', 'cleanup_pending')
		  AND updated_at <= NOW() - $1::interval
		ORDER BY updated_at, id`, fmt.Sprintf("%d seconds", int(staleAfter.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("list stale peer operations: %w", err)
	}
	defer rows.Close()

	operations := make([]models.PeerOperation, 0)
	for rows.Next() {
		operation, err := r.scanPeerOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("scan stale peer operation: %w", err)
		}
		operations = append(operations, *operation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list stale peer operations rows: %w", err)
	}
	return operations, nil
}

func (r *PeerOperationRepo) CountLive(ctx context.Context) (int64, error) {
	var count int64
	if err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM peer_operations
		WHERE state IN ('pending', 'core_applied', 'cleanup_pending')`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count live peer operations: %w", err)
	}
	return count, nil
}

func (r *PeerOperationRepo) CountCleanupPending(ctx context.Context) (int64, error) {
	var count int64
	if err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM peer_operations
		WHERE state = 'cleanup_pending'`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending peer cleanups: %w", err)
	}
	return count, nil
}

func (r *PeerOperationRepo) HasLiveByDevice(ctx context.Context, deviceID uuid.UUID) (bool, error) {
	var exists bool
	if err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM peer_operations
			WHERE device_id = $1
			  AND state IN ('pending', 'core_applied', 'cleanup_pending')
		)`, deviceID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check live device operations: %w", err)
	}
	return exists, nil
}

func (r *PeerOperationRepo) HasLiveByUser(ctx context.Context, userID uuid.UUID) (bool, error) {
	var exists bool
	if err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM peer_operations
			WHERE user_id = $1
			  AND state IN ('pending', 'core_applied', 'cleanup_pending')
		)`, userID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check live user operations: %w", err)
	}
	return exists, nil
}

// ListPendingCleanupTargets prevents the generic orphan pass from racing or
// duplicating a durable replacement or disconnect handled by its operation.
func (r *PeerOperationRepo) ListPendingCleanupTargets(ctx context.Context) ([]PendingCleanupTarget, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT previous.server_id, previous.public_key,
		       COALESCE(operation.previous_operation_id::text,
		                previous.provision_operation_id::text, '')
		FROM peer_operations operation
		JOIN peers previous ON previous.id = operation.previous_peer_id
		WHERE (operation.action IN ('connect', 'replace') AND operation.state = 'cleanup_pending')
		   OR (operation.action = 'disconnect'
		       AND operation.state IN ('pending', 'core_applied', 'cleanup_pending'))
		ORDER BY previous.server_id, previous.public_key`)
	if err != nil {
		return nil, fmt.Errorf("list pending peer cleanup targets: %w", err)
	}
	defer rows.Close()
	targets := make([]PendingCleanupTarget, 0)
	for rows.Next() {
		var target PendingCleanupTarget
		if err := rows.Scan(&target.ServerID, &target.PublicKey, &target.OperationID); err != nil {
			return nil, fmt.Errorf("scan pending peer cleanup target: %w", err)
		}
		targets = append(targets, target)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list pending peer cleanup target rows: %w", err)
	}
	return targets, nil
}

// RecordAttemptStarted persists every remote retry before it is issued. Moving
// updated_at also prevents a failed Core from being hammered every minute.
func (r *PeerOperationRepo) RecordAttemptStarted(ctx context.Context, operationID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE peer_operations
		SET attempts = attempts + 1, updated_at = NOW()
		WHERE id = $1 AND state IN ('pending', 'core_applied', 'cleanup_pending')`, operationID)
	if err != nil {
		return fmt.Errorf("start peer operation attempt: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrOperationState
	}
	return nil
}

func (r *PeerOperationRepo) RecordAttemptFailure(ctx context.Context, operationID uuid.UUID, cause error) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE peer_operations
		SET last_error = $2, updated_at = NOW()
		WHERE id = $1 AND state IN ('pending', 'core_applied', 'cleanup_pending')`,
		operationID, boundedOperationError(cause))
	if err != nil {
		return fmt.Errorf("record peer operation failure: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrOperationState
	}
	return nil
}

// CompleteCleanup closes an exact previous-peer cleanup. Repeated calls are
// idempotent so multiple Control replicas can converge safely.
func (r *PeerOperationRepo) CompleteCleanup(ctx context.Context, operationID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE peer_operations
		SET state = 'completed', last_error = '', updated_at = NOW()
		WHERE id = $1 AND state = 'cleanup_pending'`, operationID)
	if err != nil {
		return fmt.Errorf("complete peer cleanup: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var state models.PeerOperationState
	if err := r.pool.QueryRow(ctx, `SELECT state FROM peer_operations WHERE id = $1`, operationID).Scan(&state); err != nil {
		return fmt.Errorf("load completed peer cleanup: %w", err)
	}
	if state == models.PeerOperationCompleted {
		return nil
	}
	return ErrOperationState
}

func boundedOperationError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	runes := []rune(message)
	if len(runes) > 1024 {
		message = string(runes[:1024])
	}
	return message
}
