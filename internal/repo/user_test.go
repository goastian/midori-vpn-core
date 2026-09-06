package repo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/repo"
)

func TestUserRepoJITUnchangedClaimsDoNotWrite(t *testing.T) {
	pool := testPool(t)
	userRepo := repo.NewUserRepo(pool)
	ctx := context.Background()
	uid := "jit-stable-" + uuid.NewString()
	groups := []string{"midorivpn-users", "plan-pro"}

	created, err := userRepo.UpsertByAuthentikUID(ctx, uid, "stable@test.invalid", groups)
	if err != nil {
		t.Fatalf("create JIT user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, created.ID)
	})

	if _, err := pool.Exec(ctx, `UPDATE users SET updated_at = '2000-01-01 00:00:00+00' WHERE id = $1`, created.ID); err != nil {
		t.Fatalf("set updated_at sentinel: %v", err)
	}
	resolved, err := userRepo.UpsertByAuthentikUID(ctx, uid, "stable@test.invalid", groups)
	if err != nil {
		t.Fatalf("resolve unchanged JIT user: %v", err)
	}
	if resolved.UpdatedAt.Year() != 2000 {
		t.Fatalf("unchanged JIT resolution wrote updated_at: %s", resolved.UpdatedAt)
	}
}

func TestUserRepoJITUnchangedClaimsBypassRowLock(t *testing.T) {
	pool := testPool(t)
	userRepo := repo.NewUserRepo(pool)
	ctx := context.Background()
	uid := "jit-locked-" + uuid.NewString()
	groups := []string{"midorivpn-users"}

	created, err := userRepo.UpsertByAuthentikUID(ctx, uid, "locked@test.invalid", groups)
	if err != nil {
		t.Fatalf("create JIT user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, created.ID)
	})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin row lock: %v", err)
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, created.ID); err != nil {
		t.Fatalf("lock JIT user: %v", err)
	}

	resolveCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	started := time.Now()
	resolved, err := userRepo.UpsertByAuthentikUID(resolveCtx, uid, "locked@test.invalid", groups)
	if err != nil {
		t.Fatalf("unchanged JIT resolution waited on row lock: %v", err)
	}
	if resolved.ID != created.ID {
		t.Fatalf("resolved user = %s, want %s", resolved.ID, created.ID)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("unchanged JIT resolution took %s while row was locked", elapsed)
	}
}

func TestUserRepoJITChangedClaimsRemainFailClosedOnRowLock(t *testing.T) {
	pool := testPool(t)
	userRepo := repo.NewUserRepo(pool)
	ctx := context.Background()
	uid := "jit-change-" + uuid.NewString()

	created, err := userRepo.UpsertByAuthentikUID(ctx, uid, "before@test.invalid", []string{"midorivpn-users"})
	if err != nil {
		t.Fatalf("create JIT user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, created.ID)
	})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin row lock: %v", err)
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, created.ID); err != nil {
		t.Fatalf("lock JIT user: %v", err)
	}

	updateCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	_, err = userRepo.UpsertByAuthentikUID(updateCtx, uid, "changed@test.invalid", []string{"midorivpn-admins"})
	if err == nil || (!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled)) {
		t.Fatalf("changed claims under lock error = %v, want context deadline", err)
	}

	var email string
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, created.ID).Scan(&email); err != nil {
		t.Fatalf("read unchanged JIT user: %v", err)
	}
	if email != "before@test.invalid" {
		t.Fatalf("changed claims escaped failed-closed update: %q", email)
	}
}

func TestUserRepoJITConcurrentFirstProvisionConverges(t *testing.T) {
	pool := testPool(t)
	userRepo := repo.NewUserRepo(pool)
	ctx := context.Background()
	uid := "jit-concurrent-" + uuid.NewString()
	groups := []string{"midorivpn-users"}

	type result struct {
		id  uuid.UUID
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			user, err := userRepo.UpsertByAuthentikUID(ctx, uid, "concurrent@test.invalid", groups)
			var id uuid.UUID
			if user != nil {
				id = user.ID
			}
			results <- result{id: id, err: err}
		}()
	}
	close(start)
	first := <-results
	second := <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent JIT errors = %v, %v", first.err, second.err)
	}
	if first.id == uuid.Nil || first.id != second.id {
		t.Fatalf("concurrent JIT ids = %s, %s", first.id, second.id)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, first.id)
	})

	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE authentik_uid = $1`, uid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("concurrent JIT rows = %d, want 1", count)
	}
}
