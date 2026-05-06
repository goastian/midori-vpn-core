package repo

import (
	"context"
	"errors"

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

func NewTrustedExtensionRepo(pool *pgxpool.Pool) *TrustedExtensionRepo {
	return &TrustedExtensionRepo{pool: pool}
}

// IsTrusted returns true when the origin exists and has not been revoked.
func (r *TrustedExtensionRepo) IsTrusted(ctx context.Context, origin string) (bool, error) {
	var revoked bool
	err := r.pool.QueryRow(ctx,
		`SELECT revoked FROM trusted_extension_origins WHERE origin = $1`,
		origin).Scan(&revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return !revoked, nil
}

// Register inserts the origin if it doesn't exist, or bumps last_seen_at and
// seen_count if it does. Revoked origins are NOT un-revoked automatically.
// userID may be nil for unauthenticated registration paths (currently unused).
func (r *TrustedExtensionRepo) Register(ctx context.Context, origin string, userID *uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO trusted_extension_origins (origin, first_user_id, first_seen_at, last_seen_at, seen_count)
		VALUES ($1, $2, NOW(), NOW(), 1)
		ON CONFLICT (origin) DO UPDATE
		SET last_seen_at = NOW(),
		    seen_count   = trusted_extension_origins.seen_count + 1
	`, origin, userID)
	return err
}

// List returns every registered origin (including revoked ones) for admin UIs.
type TrustedExtensionOrigin struct {
	Origin      string
	Revoked     bool
	SeenCount   int64
	FirstSeenAt string
	LastSeenAt  string
}

func (r *TrustedExtensionRepo) List(ctx context.Context) ([]TrustedExtensionOrigin, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT origin, revoked, seen_count, first_seen_at::text, last_seen_at::text
		FROM trusted_extension_origins
		ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustedExtensionOrigin
	for rows.Next() {
		var o TrustedExtensionOrigin
		if err := rows.Scan(&o.Origin, &o.Revoked, &o.SeenCount, &o.FirstSeenAt, &o.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// SetRevoked toggles the revoked flag for an origin. Used by admin tooling.
func (r *TrustedExtensionRepo) SetRevoked(ctx context.Context, origin string, revoked bool) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE trusted_extension_origins SET revoked = $2 WHERE origin = $1`,
		origin, revoked)
	return err
}
