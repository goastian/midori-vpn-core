package repo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

type AuditRepo struct {
	pool *pgxpool.Pool
}

type AdminAuditListOptions struct {
	ListOptions
	Action string
}

func NewAuditRepo(pool *pgxpool.Pool) *AuditRepo {
	return &AuditRepo{pool: pool}
}

func (r *AuditRepo) Log(ctx context.Context, userID *uuid.UUID, action string, metadata map[string]interface{}, ipAddress string) error {
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		metaJSON = []byte("{}")
	}

	masked := maskIP(ipAddress)

	query := `INSERT INTO audit_logs (user_id, action, metadata, ip_address) VALUES ($1, $2, $3, $4)`
	_, err = r.pool.Exec(ctx, query, userID, action, metaJSON, masked)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}

// maskIP truncates the last octet of IPv4 or last 80 bits of IPv6,
// then appends a short hash for correlation without storing the full IP.
func maskIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || ip == "system" {
		return ip
	}

	hash := sha256.Sum256([]byte(ip))
	short := hex.EncodeToString(hash[:4])

	if idx := strings.LastIndex(ip, "."); idx != -1 {
		return ip[:idx] + ".x [" + short + "]"
	}
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		return ip[:idx] + ":x [" + short + "]"
	}
	return ip
}

func (r *AuditRepo) ListByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]models.AuditLog, error) {
	query := `
		SELECT al.id, al.user_id, COALESCE(u.email, ''), al.action, al.metadata, al.ip_address, al.created_at
		FROM audit_logs al
		LEFT JOIN users u ON u.id = al.user_id
		WHERE al.user_id = $1
		ORDER BY al.created_at DESC LIMIT $2 OFFSET $3
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
			SELECT al.id, al.user_id, COALESCE(u.email, ''), al.action, al.metadata, al.ip_address, al.created_at
			FROM audit_logs al
			LEFT JOIN users u ON u.id = al.user_id
			WHERE al.action = $1
			ORDER BY al.created_at DESC LIMIT $2 OFFSET $3
		`
		args = []interface{}{action, limit, offset}
	} else {
		query = `
			SELECT al.id, al.user_id, COALESCE(u.email, ''), al.action, al.metadata, al.ip_address, al.created_at
			FROM audit_logs al
			LEFT JOIN users u ON u.id = al.user_id
			ORDER BY al.created_at DESC LIMIT $1 OFFSET $2
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

func (r *AuditRepo) ListAdminPage(ctx context.Context, options AdminAuditListOptions) ([]models.AuditLog, int, error) {
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if options.Action != "" {
		args = append(args, options.Action)
		clauses = append(clauses, fmt.Sprintf("al.action = $%d", len(args)))
	}
	if options.Search != "" {
		args = append(args, strings.ToLower(options.Search)+"%")
		placeholder := fmt.Sprintf("$%d", len(args))
		clauses = append(clauses, fmt.Sprintf(
			"(lower(al.action) LIKE %s OR lower(COALESCE(u.email, '')) LIKE %s)",
			placeholder, placeholder,
		))
	}
	where := listWhere(clauses)
	direction := listDirection(options.Order)
	orderBy := "al.created_at " + direction + ", al.id " + direction
	if options.Sort == "action" {
		orderBy = "lower(al.action) " + direction + ", al.id " + direction
	}
	limitPlaceholder := fmt.Sprintf("$%d", len(args)+1)
	offsetPlaceholder := fmt.Sprintf("$%d", len(args)+2)
	fromSQL := " FROM audit_logs al LEFT JOIN users u ON u.id = al.user_id"
	countSQL := "SELECT COUNT(*)" + fromSQL + where
	listSQL := `
		SELECT al.id, al.user_id, COALESCE(u.email, ''), al.action,
		       al.metadata, al.ip_address, al.created_at` + fromSQL + where +
		" ORDER BY " + orderBy + " LIMIT " + limitPlaceholder + " OFFSET " + offsetPlaceholder
	logs, total, err := queryPage(ctx, r.pool, countSQL, listSQL, args, options.Limit, options.Offset,
		func(rows pgx.Rows) (models.AuditLog, error) {
			var log models.AuditLog
			var metadata []byte
			if err := rows.Scan(
				&log.ID, &log.UserID, &log.UserEmail, &log.Action,
				&metadata, &log.IPAddress, &log.CreatedAt,
			); err != nil {
				return models.AuditLog{}, fmt.Errorf("scan admin audit log: %w", err)
			}
			if err := json.Unmarshal(metadata, &log.Metadata); err != nil {
				return models.AuditLog{}, fmt.Errorf("decode admin audit metadata: %w", err)
			}
			return log, nil
		})
	if err != nil {
		return nil, 0, fmt.Errorf("list admin audit logs: %w", err)
	}
	return logs, total, nil
}

func scanAuditRows(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
}) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		var metaBytes []byte
		if err := rows.Scan(&l.ID, &l.UserID, &l.UserEmail, &l.Action, &metaBytes, &l.IPAddress, &l.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metaBytes, &l.Metadata)
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan audit rows: %w", err)
	}
	return logs, nil
}
