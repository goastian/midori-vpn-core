package repo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TrustedExtensionRepo stores browser extension origins trusted via TOFU
// (Trust On First Use). Origins are registered when an authenticated user
// successfully completes the OAuth callback. Subsequent requests are checked
// against the registered set.
type TrustedExtensionRepo struct {
	pool *pgxpool.Pool
}

type ExtensionOriginStatus uint8

const (
	ExtensionOriginUnknown ExtensionOriginStatus = iota
	ExtensionOriginTrusted
	ExtensionOriginRevoked
)

func NewTrustedExtensionRepo(pool *pgxpool.Pool) *TrustedExtensionRepo {
	return &TrustedExtensionRepo{pool: pool}
}

// IsTrusted returns true when the origin exists and has not been revoked.
func (r *TrustedExtensionRepo) IsTrusted(ctx context.Context, origin string) (bool, error) {
	status, err := r.Status(ctx, origin)
	return status == ExtensionOriginTrusted, err
}

// Status distinguishes an origin that has never completed OAuth from an
// explicitly revoked origin. Callers must not treat both states as the same:
// unknown origins may bootstrap through the PKCE callback, revoked origins may
// not.
func (r *TrustedExtensionRepo) Status(ctx context.Context, origin string) (ExtensionOriginStatus, error) {
	var revoked bool
	err := r.pool.QueryRow(ctx,
		`SELECT revoked FROM trusted_extension_origins WHERE origin = $1`,
		origin).Scan(&revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ExtensionOriginUnknown, nil
		}
		return ExtensionOriginUnknown, err
	}
	if revoked {
		return ExtensionOriginRevoked, nil
	}
	return ExtensionOriginTrusted, nil
}

// Register inserts the origin if it doesn't exist, or bumps last_seen_at and
// seen_count if it does. Revoked origins are NOT un-revoked automatically.
// userID may be nil for unauthenticated registration paths (currently unused).
func (r *TrustedExtensionRepo) Register(ctx context.Context, origin string, _ *uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO trusted_extension_origins (origin, created_at, updated_at)
		VALUES ($1, NOW(), NOW())
		ON CONFLICT (origin) DO UPDATE
		SET updated_at = NOW()
	`, origin)
	return err
}

// List returns every registered origin (including revoked ones) for admin UIs.
type TrustedExtensionOrigin struct {
	ID        uuid.UUID `json:"id"`
	Origin    string    `json:"origin"`
	Revoked   bool      `json:"revoked"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
}

func (r *TrustedExtensionRepo) List(ctx context.Context) ([]TrustedExtensionOrigin, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, origin, revoked, created_at::text, updated_at::text
		FROM trusted_extension_origins
		ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustedExtensionOrigin
	for rows.Next() {
		var o TrustedExtensionOrigin
		if err := rows.Scan(&o.ID, &o.Origin, &o.Revoked, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (r *TrustedExtensionRepo) ListAdminPage(ctx context.Context, options ListOptions) ([]TrustedExtensionOrigin, int, error) {
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if options.Search != "" {
		args = append(args, strings.ToLower(options.Search)+"%")
		clauses = append(clauses, fmt.Sprintf("lower(origin) LIKE $%d", len(args)))
	}
	switch options.Status {
	case "trusted":
		clauses = append(clauses, "revoked = FALSE")
	case "revoked":
		clauses = append(clauses, "revoked = TRUE")
	}
	where := listWhere(clauses)
	direction := listDirection(options.Order)
	orderBy := "updated_at " + direction + ", id " + direction
	switch options.Sort {
	case "created_at":
		orderBy = "created_at " + direction + ", id " + direction
	case "origin":
		orderBy = "lower(origin) " + direction + ", id " + direction
	}
	limitPlaceholder := fmt.Sprintf("$%d", len(args)+1)
	offsetPlaceholder := fmt.Sprintf("$%d", len(args)+2)
	countSQL := "SELECT COUNT(*) FROM trusted_extension_origins" + where
	listSQL := `SELECT id, origin, revoked, created_at::text, updated_at::text
		FROM trusted_extension_origins` + where + " ORDER BY " + orderBy +
		" LIMIT " + limitPlaceholder + " OFFSET " + offsetPlaceholder
	origins, total, err := queryPage(ctx, r.pool, countSQL, listSQL, args, options.Limit, options.Offset,
		func(rows pgx.Rows) (TrustedExtensionOrigin, error) {
			var origin TrustedExtensionOrigin
			if err := rows.Scan(&origin.ID, &origin.Origin, &origin.Revoked, &origin.CreatedAt, &origin.UpdatedAt); err != nil {
				return TrustedExtensionOrigin{}, fmt.Errorf("scan admin extension origin: %w", err)
			}
			return origin, nil
		})
	if err != nil {
		return nil, 0, fmt.Errorf("list admin extension origins: %w", err)
	}
	return origins, total, nil
}

// SetRevokedByID toggles the revoked flag for an origin. Used by admin tooling.
func (r *TrustedExtensionRepo) SetRevokedByID(ctx context.Context, id uuid.UUID, revoked bool) (string, error) {
	var origin string
	err := r.pool.QueryRow(ctx,
		`UPDATE trusted_extension_origins SET revoked = $2, updated_at = NOW() WHERE id = $1 RETURNING origin`,
		id, revoked).Scan(&origin)
	return origin, err
}
