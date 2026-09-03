package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

var (
	ErrDeviceRevoked   = errors.New("device is revoked")
	ErrAmbiguousDevice = errors.New("legacy device identity is ambiguous")
)

const deviceColumns = `id, user_id, client_instance_id, reported_name,
	COALESCE(alias, ''), device_type, COALESCE(adapter_reference, ''),
	first_seen_at, last_seen_at, revoked_at`

type DeviceRepo struct {
	pool *pgxpool.Pool
}

func NewDeviceRepo(pool *pgxpool.Pool) *DeviceRepo {
	return &DeviceRepo{pool: pool}
}

func (r *DeviceRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.Device, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+deviceColumns+`
		FROM devices
		WHERE user_id = $1
		ORDER BY revoked_at NULLS FIRST, last_seen_at DESC, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	devices := make([]models.Device, 0)
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		devices = append(devices, *device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list devices rows: %w", err)
	}
	return devices, nil
}

func (r *DeviceRepo) GetByUser(ctx context.Context, userID, deviceID uuid.UUID) (*models.Device, error) {
	device, err := scanDevice(r.pool.QueryRow(ctx, `
		SELECT `+deviceColumns+`
		FROM devices
		WHERE id = $1 AND user_id = $2`, deviceID, userID))
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}
	return device, nil
}

func (r *DeviceRepo) UpdateAlias(ctx context.Context, userID, deviceID uuid.UUID, alias string) (*models.Device, error) {
	device, err := scanDevice(r.pool.QueryRow(ctx, `
		UPDATE devices
		SET alias = NULLIF($3, '')
		WHERE id = $1 AND user_id = $2
		RETURNING `+deviceColumns, deviceID, userID, alias))
	if err != nil {
		return nil, fmt.Errorf("update device alias: %w", err)
	}
	return device, nil
}

// RevokeWithMaterial atomically revokes a device after its active Core peer
// has been removed. Session rows remain as audit history, while recoverable
// PSKs and active client certificates are invalidated.
func (r *DeviceRepo) RevokeWithMaterial(ctx context.Context, userID, deviceID uuid.UUID) (*models.Device, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin device revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := scanDevice(tx.QueryRow(ctx, `
		SELECT `+deviceColumns+`
		FROM devices
		WHERE id = $1 AND user_id = $2
		FOR UPDATE`, deviceID, userID)); err != nil {
		return nil, fmt.Errorf("lock device for revocation: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		WITH deactivated AS (
			UPDATE peers
			SET is_active = FALSE
			WHERE user_id = $1 AND device_id = $2 AND is_active = TRUE
			RETURNING server_id
		), counts AS (
			SELECT server_id, COUNT(*)::INTEGER AS removed
			FROM deactivated
			GROUP BY server_id
		)
		UPDATE vpn_servers AS server
		SET current_peers = GREATEST(server.current_peers - counts.removed, 0),
		    updated_at = NOW()
		FROM counts
		WHERE server.id = counts.server_id`, userID, deviceID); err != nil {
		return nil, fmt.Errorf("deactivate device sessions: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE peers
		SET preshared_key = ''
		WHERE user_id = $1 AND device_id = $2 AND preshared_key <> ''`, userID, deviceID); err != nil {
		return nil, fmt.Errorf("invalidate device session material: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE device_certificates
		SET revoked_at = NOW(), revocation_reason = 'device-revoked'
		WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL`, userID, deviceID); err != nil {
		return nil, fmt.Errorf("revoke device certificates: %w", err)
	}

	device, err := scanDevice(tx.QueryRow(ctx, `
		UPDATE devices
		SET revoked_at = COALESCE(revoked_at, NOW())
		WHERE id = $1 AND user_id = $2
		RETURNING `+deviceColumns, deviceID, userID))
	if err != nil {
		return nil, fmt.Errorf("revoke device: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit device revocation: %w", err)
	}
	return device, nil
}

// ResolveRegistered returns the stable device for an installation, updating
// observations without ever replacing its user alias. A sole active legacy
// device with the same reported name is adopted; ambiguous matches remain
// separate for manual review.
func (r *DeviceRepo) ResolveRegistered(
	ctx context.Context,
	userID, clientInstanceID uuid.UUID,
	reportedName string,
	deviceType models.DeviceType,
	adapterReference string,
) (*models.Device, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin device resolution: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	device, err := scanDevice(tx.QueryRow(ctx, `
		SELECT `+deviceColumns+`
		FROM devices
		WHERE user_id = $1 AND client_instance_id = $2
		FOR UPDATE`, userID, clientInstanceID))
	if err == nil {
		if device.RevokedAt != nil {
			return nil, ErrDeviceRevoked
		}
		device, err = updateRegisteredDevice(ctx, tx, device.ID, reportedName, deviceType, adapterReference)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit device update: %w", err)
		}
		return device, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("find registered device: %w", err)
	}

	legacy, ambiguous, err := soleLegacyDevice(ctx, tx, userID, reportedName)
	if err != nil {
		return nil, err
	}
	if legacy != nil && !ambiguous {
		device, err = scanDevice(tx.QueryRow(ctx, `
			UPDATE devices
			SET client_instance_id = $2,
			    reported_name = $3,
			    device_type = $4,
			    adapter_reference = NULLIF($5, ''),
			    last_seen_at = GREATEST(last_seen_at, NOW())
			WHERE id = $1 AND client_instance_id IS NULL AND revoked_at IS NULL
			RETURNING `+deviceColumns,
			legacy.ID, clientInstanceID, reportedName, deviceType, adapterReference))
		if err == nil {
			if err := tx.Commit(ctx); err != nil {
				return nil, fmt.Errorf("commit legacy device adoption: %w", err)
			}
			return device, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("adopt legacy device: %w", err)
		}
	}

	device, err = scanDevice(tx.QueryRow(ctx, `
		INSERT INTO devices (
			user_id, client_instance_id, reported_name, device_type,
			adapter_reference
		)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''))
		ON CONFLICT ON CONSTRAINT uq_devices_user_client_instance
		DO UPDATE SET
			reported_name = EXCLUDED.reported_name,
			device_type = EXCLUDED.device_type,
			adapter_reference = EXCLUDED.adapter_reference,
			last_seen_at = GREATEST(devices.last_seen_at, NOW())
		WHERE devices.revoked_at IS NULL
		RETURNING `+deviceColumns,
		userID, clientInstanceID, reportedName, deviceType, adapterReference))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeviceRevoked
	}
	if err != nil {
		return nil, fmt.Errorf("create registered device: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit registered device: %w", err)
	}
	return device, nil
}

func updateRegisteredDevice(
	ctx context.Context,
	tx pgx.Tx,
	deviceID uuid.UUID,
	reportedName string,
	deviceType models.DeviceType,
	adapterReference string,
) (*models.Device, error) {
	device, err := scanDevice(tx.QueryRow(ctx, `
		UPDATE devices
		SET reported_name = $2,
		    device_type = $3,
		    adapter_reference = NULLIF($4, ''),
		    last_seen_at = GREATEST(last_seen_at, NOW())
		WHERE id = $1 AND revoked_at IS NULL
		RETURNING `+deviceColumns,
		deviceID, reportedName, deviceType, adapterReference))
	if err != nil {
		return nil, fmt.Errorf("update registered device: %w", err)
	}
	return device, nil
}

func soleLegacyDevice(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reportedName string) (*models.Device, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT `+deviceColumns+`
		FROM devices d
		WHERE d.user_id = $1
		  AND d.client_instance_id IS NULL
		  AND d.revoked_at IS NULL
		  AND lower(d.reported_name) = lower($2)
		  AND EXISTS (
		      SELECT 1
		      FROM peers p
		      WHERE p.device_id = d.id AND p.is_active = TRUE
		      UNION ALL
		      SELECT 1
		      FROM device_certificates c
		      WHERE c.device_id = d.id AND c.revoked_at IS NULL
		  )
		ORDER BY d.first_seen_at, d.id
		LIMIT 2
		FOR UPDATE`, userID, reportedName)
	if err != nil {
		return nil, false, fmt.Errorf("find legacy device candidate: %w", err)
	}
	defer rows.Close()

	var candidates []models.Device
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, false, fmt.Errorf("scan legacy device candidate: %w", err)
		}
		candidates = append(candidates, *device)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("list legacy device candidates: %w", err)
	}
	if len(candidates) == 0 {
		return nil, false, nil
	}
	return &candidates[0], len(candidates) > 1, nil
}

// CreateLegacy creates an intentionally ungrouped device for a client that
// has no persistent installation identifier.
func (r *DeviceRepo) CreateLegacy(ctx context.Context, userID uuid.UUID, reportedName string) (*models.Device, error) {
	device, err := scanDevice(r.pool.QueryRow(ctx, `
		INSERT INTO devices (user_id, reported_name, device_type)
		VALUES ($1, $2, 'manual')
		RETURNING `+deviceColumns, userID, reportedName))
	if err != nil {
		return nil, fmt.Errorf("create legacy device: %w", err)
	}
	return device, nil
}

// FindSoleLegacyForCertificate finds a legacy device already associated with
// exactly one active peer or certificate for the same server and name.
func (r *DeviceRepo) FindSoleLegacyForCertificate(
	ctx context.Context,
	userID, serverID uuid.UUID,
	reportedName string,
) (*models.Device, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT `+deviceColumns+`
		FROM devices d
		WHERE d.user_id = $1
		  AND d.client_instance_id IS NULL
		  AND d.revoked_at IS NULL
		  AND lower(d.reported_name) = lower($3)
		  AND d.id IN (
		      SELECT p.device_id
		      FROM peers p
		      WHERE p.user_id = $1 AND p.server_id = $2
		        AND p.is_active = TRUE
		        AND lower(p.device_name) = lower($3)
		      UNION
		      SELECT c.device_id
		      FROM device_certificates c
		      WHERE c.user_id = $1 AND c.server_id = $2
		        AND c.revoked_at IS NULL
		        AND lower(c.device_name) = lower($3)
		  )
		ORDER BY d.first_seen_at, d.id
		LIMIT 2`, userID, serverID, reportedName)
	if err != nil {
		return nil, fmt.Errorf("find legacy certificate device: %w", err)
	}
	defer rows.Close()

	var candidates []models.Device
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan legacy certificate device: %w", err)
		}
		candidates = append(candidates, *device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list legacy certificate devices: %w", err)
	}
	switch len(candidates) {
	case 0:
		return nil, pgx.ErrNoRows
	case 1:
		return &candidates[0], nil
	default:
		return nil, ErrAmbiguousDevice
	}
}

func (r *DeviceRepo) HasActiveSession(ctx context.Context, userID, deviceID uuid.UUID) (bool, error) {
	var active bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM peers
			WHERE user_id = $1 AND device_id = $2 AND is_active = TRUE
		)`, userID, deviceID).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("check active device session: %w", err)
	}
	return active, nil
}

func (r *DeviceRepo) TouchLastSeen(ctx context.Context, deviceID uuid.UUID, observedAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE devices
		SET last_seen_at = GREATEST(last_seen_at, $2)
		WHERE id = $1`, deviceID, observedAt)
	if err != nil {
		return fmt.Errorf("update device last seen: %w", err)
	}
	return nil
}

func (r *DeviceRepo) ActiveUsageByUser(ctx context.Context, userID uuid.UUID) (map[models.DeviceType]int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT d.device_type, COUNT(*)
		FROM devices d
		WHERE d.user_id = $1
		  AND EXISTS (
		      SELECT 1 FROM peers p
		      WHERE p.device_id = d.id AND p.is_active = TRUE
		  )
		GROUP BY d.device_type`, userID)
	if err != nil {
		return nil, fmt.Errorf("count active devices: %w", err)
	}
	defer rows.Close()

	usage := make(map[models.DeviceType]int)
	for rows.Next() {
		var deviceType models.DeviceType
		var count int
		if err := rows.Scan(&deviceType, &count); err != nil {
			return nil, fmt.Errorf("scan active device usage: %w", err)
		}
		usage[deviceType] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active device usage: %w", err)
	}
	return usage, nil
}

func scanDevice(row interface{ Scan(...interface{}) error }) (*models.Device, error) {
	var device models.Device
	if err := row.Scan(
		&device.ID, &device.UserID, &device.ClientInstanceID, &device.ReportedName,
		&device.Alias, &device.DeviceType, &device.AdapterReference,
		&device.FirstSeenAt, &device.LastSeenAt, &device.RevokedAt,
	); err != nil {
		return nil, err
	}
	device.DisplayName = device.ReportedName
	if device.Alias != "" {
		device.DisplayName = device.Alias
	}
	return &device, nil
}
