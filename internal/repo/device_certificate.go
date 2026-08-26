package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

type DeviceCertificateRepo struct {
	pool *pgxpool.Pool
}

func NewDeviceCertificateRepo(pool *pgxpool.Pool) *DeviceCertificateRepo {
	return &DeviceCertificateRepo{pool: pool}
}

const deviceCertificateColumns = `id, user_id, server_id, device_name, serial_number,
	certificate_pem, public_key_sha256, not_before, not_after, revoked_at,
	revocation_reason, created_at`

// ReplaceActive revokes the previous certificate for this device and inserts
// the replacement atomically, so the partial unique index is never bypassed.
func (r *DeviceCertificateRepo) ReplaceActive(ctx context.Context, certificate *models.DeviceCertificate) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin certificate replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE device_certificates
		SET revoked_at = NOW(), revocation_reason = 'superseded'
		WHERE user_id = $1 AND server_id = $2 AND lower(device_name) = lower($3)
		  AND revoked_at IS NULL`, certificate.UserID, certificate.ServerID, certificate.DeviceName); err != nil {
		return fmt.Errorf("revoke superseded certificate: %w", err)
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO device_certificates
			(id, user_id, server_id, device_name, serial_number, certificate_pem,
			 public_key_sha256, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING created_at`, certificate.ID, certificate.UserID, certificate.ServerID,
		certificate.DeviceName, certificate.SerialNumber, certificate.CertificatePEM,
		certificate.PublicKeySHA256, certificate.NotBefore, certificate.NotAfter,
	).Scan(&certificate.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert device certificate: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit certificate replacement: %w", err)
	}
	return nil
}

func (r *DeviceCertificateRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]models.DeviceCertificate, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+deviceCertificateColumns+`
		FROM device_certificates WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list device certificates: %w", err)
	}
	defer rows.Close()
	var certificates []models.DeviceCertificate
	for rows.Next() {
		certificate, err := scanDeviceCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, *certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list device certificates rows: %w", err)
	}
	return certificates, nil
}

func (r *DeviceCertificateRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.DeviceCertificate, error) {
	certificate, err := scanDeviceCertificate(r.pool.QueryRow(ctx,
		`SELECT `+deviceCertificateColumns+` FROM device_certificates WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("get device certificate: %w", err)
	}
	return certificate, nil
}

func (r *DeviceCertificateRepo) HasActiveDevice(ctx context.Context, userID, serverID uuid.UUID, deviceName string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM device_certificates
		WHERE user_id = $1 AND server_id = $2 AND lower(device_name) = lower($3)
		  AND revoked_at IS NULL AND not_after > NOW()
	)`, userID, serverID, deviceName).Scan(&exists)
	return exists, err
}

func (r *DeviceCertificateRepo) CountActiveByUser(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_certificates
		WHERE user_id = $1 AND revoked_at IS NULL AND not_after > NOW()`, userID).Scan(&count)
	return count, err
}

func (r *DeviceCertificateRepo) Revoke(ctx context.Context, id, userID uuid.UUID, reason string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE device_certificates SET revoked_at = NOW(), revocation_reason = $3
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, id, userID, reason)
	if err != nil {
		return false, fmt.Errorf("revoke device certificate: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

type RevokedCertificate struct {
	SerialNumber string
	RevokedAt    time.Time
	Reason       string
}

func (r *DeviceCertificateRepo) ListRevoked(ctx context.Context) ([]RevokedCertificate, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT serial_number, revoked_at, revocation_reason
		FROM device_certificates
		WHERE revoked_at IS NOT NULL AND not_after > NOW()
		ORDER BY revoked_at`)
	if err != nil {
		return nil, fmt.Errorf("list revoked certificates: %w", err)
	}
	defer rows.Close()
	var revoked []RevokedCertificate
	for rows.Next() {
		var entry RevokedCertificate
		if err := rows.Scan(&entry.SerialNumber, &entry.RevokedAt, &entry.Reason); err != nil {
			return nil, err
		}
		revoked = append(revoked, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list revoked certificates rows: %w", err)
	}
	return revoked, nil
}

func scanDeviceCertificate(row interface{ Scan(...interface{}) error }) (*models.DeviceCertificate, error) {
	var certificate models.DeviceCertificate
	err := row.Scan(
		&certificate.ID, &certificate.UserID, &certificate.ServerID, &certificate.DeviceName,
		&certificate.SerialNumber, &certificate.CertificatePEM, &certificate.PublicKeySHA256,
		&certificate.NotBefore, &certificate.NotAfter, &certificate.RevokedAt,
		&certificate.RevocationReason, &certificate.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}
