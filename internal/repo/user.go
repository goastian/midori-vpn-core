package repo

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

func (r *UserRepo) UpsertByAuthentikUID(ctx context.Context, authentikUID, email string, groups []string) (*models.User, error) {
	query := `
		INSERT INTO users (authentik_uid, email, groups, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (authentik_uid) DO UPDATE
		SET email = EXCLUDED.email,
		    groups = EXCLUDED.groups,
		    updated_at = NOW()
		RETURNING id, authentik_uid, email, groups, created_at, updated_at
	`

	var user models.User
	err := r.pool.QueryRow(ctx, query, authentikUID, email, groups).Scan(
		&user.ID, &user.AuthentikUID, &user.Email, &user.Groups, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert user: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `SELECT id, authentik_uid, email, groups, created_at, updated_at FROM users WHERE id = $1`
	var user models.User
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.AuthentikUID, &user.Email, &user.Groups, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return &user, nil
}

func (r *UserRepo) List(ctx context.Context, limit, offset int) ([]models.User, error) {
	query := `SELECT id, authentik_uid, email, groups, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.AuthentikUID, &u.Email, &u.Groups, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}
