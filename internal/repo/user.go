package repo

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

const userColumns = `id, authentik_uid, email, display_name, groups, is_banned, banned_at, ban_reason, created_at, updated_at`

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

func scanUser(row interface{ Scan(...interface{}) error }) (*models.User, error) {
	var u models.User
	err := row.Scan(
		&u.ID, &u.AuthentikUID, &u.Email, &u.DisplayName, &u.Groups,
		&u.IsBanned, &u.BannedAt, &u.BanReason, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) UpsertByAuthentikUID(ctx context.Context, authentikUID, email string, groups []string) (*models.User, error) {
	query := `
		INSERT INTO users (authentik_uid, email, groups, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (authentik_uid) DO UPDATE
		SET email = EXCLUDED.email,
		    groups = EXCLUDED.groups,
		    updated_at = NOW()
		RETURNING ` + userColumns

	u, err := scanUser(r.pool.QueryRow(ctx, query, authentikUID, email, groups))
	if err != nil {
		return nil, fmt.Errorf("upsert user: %w", err)
	}
	return u, nil
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	u, err := scanUser(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

func (r *UserRepo) List(ctx context.Context, limit, offset int) ([]models.User, error) {
	query := `SELECT ` + userColumns + ` FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users rows: %w", err)
	}
	return users, nil
}

func (r *UserRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func (r *UserRepo) Update(ctx context.Context, u *models.User) error {
	query := `
		UPDATE users SET email = $1, display_name = $2, groups = $3, updated_at = NOW()
		WHERE id = $4
	`
	_, err := r.pool.Exec(ctx, query, u.Email, u.DisplayName, u.Groups, u.ID)
	return err
}

func (r *UserRepo) Ban(ctx context.Context, id uuid.UUID, reason string) error {
	query := `UPDATE users SET is_banned = TRUE, banned_at = NOW(), ban_reason = $1, updated_at = NOW() WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, reason, id)
	return err
}

func (r *UserRepo) Unban(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET is_banned = FALSE, banned_at = NULL, ban_reason = '', updated_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

func (r *UserRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (r *UserRepo) Create(ctx context.Context, u *models.User) error {
	query := `
		INSERT INTO users (authentik_uid, email, display_name, groups)
		VALUES ($1, $2, $3, $4)
		RETURNING ` + userColumns
	scanned, err := scanUser(r.pool.QueryRow(ctx, query, u.AuthentikUID, u.Email, u.DisplayName, u.Groups))
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	*u = *scanned
	return nil
}
