package repo

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
)

var ErrActiveDevicesMustBeDisconnected = errors.New("active devices must be disconnected")

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
	if groups == nil {
		groups = []string{}
	}
	// Authenticated requests overwhelmingly carry claims that are already in
	// sync. Resolve that path with a plain MVCC read so unrelated connection
	// lifecycle transactions holding the user row cannot block every request.
	// A real claim change still uses the conditional upsert below and therefore
	// remains serialized and fail-closed.
	existing, err := r.getByAuthentikUID(ctx, authentikUID)
	if err == nil && existing.Email == email && slices.Equal(existing.Groups, groups) {
		return existing, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("resolve JIT user: %w", err)
	}

	query := `
		INSERT INTO users (authentik_uid, email, groups, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (authentik_uid) DO UPDATE
		SET email = EXCLUDED.email,
		    groups = EXCLUDED.groups,
		    updated_at = NOW()
		WHERE users.email IS DISTINCT FROM EXCLUDED.email
		   OR users.groups IS DISTINCT FROM EXCLUDED.groups
		RETURNING ` + userColumns

	u, err := scanUser(r.pool.QueryRow(ctx, query, authentikUID, email, groups))
	if errors.Is(err, pgx.ErrNoRows) {
		// A concurrent request may have installed these exact claims between the
		// read and upsert. Return that committed row without manufacturing a
		// second write solely to obtain RETURNING data.
		u, err = r.getByAuthentikUID(ctx, authentikUID)
	}
	if err != nil {
		return nil, fmt.Errorf("upsert user: %w", err)
	}
	return u, nil
}

func (r *UserRepo) getByAuthentikUID(ctx context.Context, authentikUID string) (*models.User, error) {
	query := `SELECT ` + userColumns + ` FROM users WHERE authentik_uid = $1`
	return scanUser(r.pool.QueryRow(ctx, query, authentikUID))
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

func (r *UserRepo) ListAdminPage(ctx context.Context, options ListOptions) ([]models.User, int, error) {
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if options.Search != "" {
		args = append(args, strings.ToLower(options.Search)+"%")
		placeholder := fmt.Sprintf("$%d", len(args))
		clauses = append(clauses, fmt.Sprintf(
			"(lower(email) LIKE %s OR lower(display_name) LIKE %s OR lower(authentik_uid) LIKE %s)",
			placeholder, placeholder, placeholder,
		))
	}
	switch options.Status {
	case "active":
		clauses = append(clauses, "is_banned = FALSE")
	case "banned":
		clauses = append(clauses, "is_banned = TRUE")
	}
	where := listWhere(clauses)
	direction := listDirection(options.Order)
	orderBy := "created_at " + direction + ", id " + direction
	switch options.Sort {
	case "email":
		orderBy = "lower(email) " + direction + ", id " + direction
	case "display_name":
		orderBy = "lower(display_name) " + direction + ", id " + direction
	}
	limitPlaceholder := fmt.Sprintf("$%d", len(args)+1)
	offsetPlaceholder := fmt.Sprintf("$%d", len(args)+2)
	countSQL := "SELECT COUNT(*) FROM users" + where
	listSQL := "SELECT " + userColumns + " FROM users" + where +
		" ORDER BY " + orderBy + " LIMIT " + limitPlaceholder + " OFFSET " + offsetPlaceholder

	users, total, err := queryPage(ctx, r.pool, countSQL, listSQL, args, options.Limit, options.Offset,
		func(rows pgx.Rows) (models.User, error) {
			user, err := scanUser(rows)
			if err != nil {
				return models.User{}, fmt.Errorf("scan admin user: %w", err)
			}
			return *user, nil
		})
	if err != nil {
		return nil, 0, fmt.Errorf("list admin users: %w", err)
	}
	return users, total, nil
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
	tag, err := r.pool.Exec(ctx, query, reason, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	return nil
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

// DeleteIfDrained prevents cascading deletion from hiding active access or a
// live operation. The user row is locked first, matching BeginConnect and Ban.
func (r *UserRepo) DeleteIfDrained(ctx context.Context, id uuid.UUID) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin drained user deletion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, id).Scan(&userID); err != nil {
		return fmt.Errorf("lock user for deletion: %w", err)
	}
	var blockers int
	if err := tx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM peers WHERE user_id = $1 AND is_active = TRUE) +
			(SELECT COUNT(*) FROM peer_operations
			 WHERE user_id = $1
			   AND state IN ('pending', 'core_applied', 'cleanup_pending'))`, id).Scan(&blockers); err != nil {
		return fmt.Errorf("count user deletion blockers: %w", err)
	}
	if blockers > 0 {
		return ErrActiveDevicesMustBeDisconnected
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete drained user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit drained user deletion: %w", err)
	}
	return nil
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
