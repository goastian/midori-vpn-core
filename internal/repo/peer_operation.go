package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

var (
	ErrConnectionInProgress  = errors.New("connection operation is already in progress")
	ErrDeviceLimitReached    = errors.New("device limit reached")
	ErrServerCapacity        = errors.New("server is full or inactive")
	ErrOperationState        = errors.New("peer operation is in an invalid state")
	ErrPeerOperationConflict = errors.New("public key belongs to another device")
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

type PeerOperationRepo struct {
	pool *pgxpool.Pool
}

func NewPeerOperationRepo(pool *pgxpool.Pool) *PeerOperationRepo {
	return &PeerOperationRepo{pool: pool}
}

const operationColumns = `id, action, state, user_id, device_id, server_id,
	public_key, preshared_key, pq_kem_ciphertext, previous_peer_id,
	COALESCE(assigned_ip, ''), capacity_reserved, attempts, last_error,
	core_applied_at, completed_at, created_at, updated_at`

func scanPeerOperation(row interface{ Scan(...interface{}) error }) (*models.PeerOperation, error) {
	var operation models.PeerOperation
	if err := row.Scan(
		&operation.ID, &operation.Action, &operation.State, &operation.UserID,
		&operation.DeviceID, &operation.ServerID, &operation.PublicKey,
		&operation.PresharedKey, &operation.PQKEMCiphertext,
		&operation.PreviousPeerID, &operation.AssignedIP,
		&operation.CapacityReserved, &operation.Attempts,
		&operation.LastError, &operation.CoreAppliedAt, &operation.CompletedAt,
		&operation.CreatedAt, &operation.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &operation, nil
}

const operationPeerColumns = `id, user_id, server_id, public_key,
	COALESCE(preshared_key, ''), assigned_ip, is_active, device_name, device_id,
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
	operation, err := scanPeerOperation(r.pool.QueryRow(ctx, `
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
	return operation, peer, nil
}

// BeginConnect serializes a user's connection changes, locks the installation
// and absent public-key namespace, rechecks quota/capacity, then durably
// reserves the target server slot in the same transaction as the operation.
func (r *PeerOperationRepo) BeginConnect(ctx context.Context, params BeginConnectParams) (*BeginConnectResult, error) {
	if params.OperationID == uuid.Nil {
		return nil, errors.New("connection operation ID is required")
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
			operation, err = scanPeerOperation(tx.QueryRow(ctx, `
				SELECT `+operationColumns+` FROM peer_operations WHERE id = $1`, *existingPeer.ProvisionOperationID))
			if err != nil {
				return nil, fmt.Errorf("load existing connection operation: %w", err)
			}
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

	var active bool
	var currentPeers, maxPeers int
	if err := tx.QueryRow(ctx, `
		SELECT is_active, current_peers, max_peers
		FROM vpn_servers WHERE id = $1 FOR UPDATE`, params.ServerID).Scan(&active, &currentPeers, &maxPeers); err != nil {
		return nil, fmt.Errorf("lock connection server: %w", err)
	}
	capacityReserved := previousPeer == nil || previousPeer.ServerID != params.ServerID
	if !active || (capacityReserved && currentPeers >= maxPeers) {
		return nil, ErrServerCapacity
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
	if previousPeer != nil {
		action = models.PeerOperationReplace
		previousPeerID = &previousPeer.ID
	}
	operation, err := scanPeerOperation(tx.QueryRow(ctx, `
		INSERT INTO peer_operations (
			id, action, state, user_id, device_id, server_id, public_key,
			preshared_key, pq_kem_ciphertext, previous_peer_id,
			capacity_reserved, attempts
		) VALUES ($1, $2, 'pending', $3, $4, $5, $6, $7, $8, $9, $10, 1)
		RETURNING `+operationColumns,
		params.OperationID, action, params.UserID, device.ID, params.ServerID,
		params.PublicKey, params.PresharedKey, params.PQKEMCiphertext,
		previousPeerID, capacityReserved))
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

// CompleteConnect creates the active peer, retires the prior database session,
// and finalizes counters and operation state atomically. Core cleanup follows
// this commit and can be marked cleanup_pending without losing either owner.
func (r *PeerOperationRepo) CompleteConnect(ctx context.Context, operationID uuid.UUID) (*models.Peer, *models.Peer, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("begin connection completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	operation, err := scanPeerOperation(tx.QueryRow(ctx, `
		SELECT `+operationColumns+` FROM peer_operations
		WHERE id = $1 FOR UPDATE`, operationID))
	if err != nil {
		return nil, nil, fmt.Errorf("lock connection operation: %w", err)
	}
	if operation.State == models.PeerOperationCompleted || operation.State == models.PeerOperationCleanupPending {
		peer, peerErr := scanOperationPeer(tx.QueryRow(ctx, `
			SELECT `+operationPeerColumns+` FROM peers
			WHERE provision_operation_id = $1 AND is_active = TRUE`, operationID))
		return peer, nil, peerErr
	}
	if operation.State != models.PeerOperationCoreApplied {
		return nil, nil, ErrOperationState
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
			if _, err := tx.Exec(ctx, `UPDATE peers SET is_active = FALSE WHERE id = $1`, previousPeer.ID); err != nil {
				return nil, nil, fmt.Errorf("retire previous peer: %w", err)
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
	peer, err := scanOperationPeer(tx.QueryRow(ctx, `
		INSERT INTO peers (
			user_id, server_id, public_key, preshared_key, assigned_ip,
			device_name, device_id, provision_operation_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+operationPeerColumns,
		operation.UserID, operation.ServerID, operation.PublicKey,
		operation.PresharedKey, operation.AssignedIP, deviceName,
		operation.DeviceID, operation.ID))
	if err != nil {
		return nil, nil, fmt.Errorf("create completed peer: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE peer_operations
		SET state = 'completed', completed_at = NOW(), last_error = '',
		    updated_at = NOW()
		WHERE id = $1`, operation.ID); err != nil {
		return nil, nil, fmt.Errorf("complete peer operation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit completed peer operation: %w", err)
	}
	return peer, previousPeer, nil
}

func (r *PeerOperationRepo) FailDefinitively(ctx context.Context, operationID uuid.UUID, cause error) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	operation, err := scanPeerOperation(tx.QueryRow(ctx, `
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
		WHERE id = $1 AND state = 'completed'`, operationID, boundedOperationError(cause))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrOperationState
	}
	return nil
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
