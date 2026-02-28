package repo

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

type AuditRepo struct {
	pool *pgxpool.Pool
}

func NewAuditRepo(pool *pgxpool.Pool) *AuditRepo {
	return &AuditRepo{pool: pool}
}

func (r *AuditRepo) Log(ctx context.Context, userID *uuid.UUID, action string, metadata map[string]interface{}, ipAddress string) error {
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	query := `INSERT INTO audit_logs (user_id, action, metadata, ip_address) VALUES ($1, $2, $3, $4)`
	_, err = r.pool.Exec(ctx, query, userID, action, metaJSON, ipAddress)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}

func (r *AuditRepo) ListByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]models.AuditLog, error) {
	query := `
		SELECT id, user_id, action, metadata, ip_address, created_at
		FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
	`
	rows, err := r.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditRows(rows)
}

func (r *AuditRepo) ListAll(ctx context.Context, limit, offset int, action string) ([]models.AuditLog, error) {
	var query string
	var args []interface{}

	if action != "" {
		query = `
			SELECT id, user_id, action, metadata, ip_address, created_at
			FROM audit_logs WHERE action = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
		`
		args = []interface{}{action, limit, offset}
	} else {
		query = `
			SELECT id, user_id, action, metadata, ip_address, created_at
			FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list all audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditRows(rows)
}

func scanAuditRows(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
}) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		var metaBytes []byte
		if err := rows.Scan(&l.ID, &l.UserID, &l.Action, &metaBytes, &l.IPAddress, &l.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metaBytes, &l.Metadata)
		logs = append(logs, l)
	}
	return logs, nil
}
