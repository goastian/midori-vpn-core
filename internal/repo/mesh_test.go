package repo_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/db"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

// testPool connects to a real PostgreSQL instance using the TEST_DATABASE_URL
// environment variable and runs all pending migrations. The test is skipped if
// the variable is not set.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}

	if err := db.RunMigrations(dsn); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// insertTestUser creates a minimal user row and returns its ID.
func insertTestUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (authentik_uid, email, display_name)
		 VALUES ($1, $2, $3)
		 RETURNING id`,
		uuid.New().String(), uuid.New().String()+"@test.invalid", "Test User",
	).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestUser: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

// insertTestMesh creates a mesh via the repo and returns the mesh.
func insertTestMesh(t *testing.T, r *repo.MeshRepo, ownerID uuid.UUID) *models.MeshNetwork {
	t.Helper()
	subnet, err := r.NextAvailableSubnet(context.Background())
	if err != nil {
		t.Fatalf("NextAvailableSubnet: %v", err)
	}
	mesh := &models.MeshNetwork{
		Name:       "Test Mesh",
		OwnerID:    ownerID,
		Subnet:     subnet,
		MaxMembers: 10,
	}
	if err := r.Create(context.Background(), mesh); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		r.Delete(context.Background(), mesh.ID)
	})
	return mesh
}

// ──────────────────────────────────────────────────────────────────────────────

func TestMeshRepo_CreateAndGetByID(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)

	mesh := insertTestMesh(t, r, ownerID)

	if mesh.ID == uuid.Nil {
		t.Fatal("expected non-nil mesh ID after Create")
	}
	if mesh.InviteCode == "" {
		t.Fatal("expected non-empty invite code after Create")
	}
	if _, err := uuid.Parse(mesh.InviteCode); err != nil {
		t.Fatalf("invite code is not a valid UUID: %q — %v", mesh.InviteCode, err)
	}

	got, err := r.GetByID(context.Background(), mesh.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Name != mesh.Name {
		t.Errorf("Name = %q; want %q", got.Name, mesh.Name)
	}
	if got.Subnet != mesh.Subnet {
		t.Errorf("Subnet = %q; want %q", got.Subnet, mesh.Subnet)
	}
}

func TestMeshRepo_InviteCodeIsValidUUID(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	mesh := insertTestMesh(t, r, ownerID)

	if _, err := uuid.Parse(mesh.InviteCode); err != nil {
		t.Fatalf("generated invite code %q is not a valid UUID: %v", mesh.InviteCode, err)
	}
}

func TestMeshRepo_GetByInviteCode(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	mesh := insertTestMesh(t, r, ownerID)

	got, err := r.GetByInviteCode(context.Background(), mesh.InviteCode)
	if err != nil {
		t.Fatalf("GetByInviteCode: %v", err)
	}
	if got.ID != mesh.ID {
		t.Errorf("ID = %v; want %v", got.ID, mesh.ID)
	}
}

func TestMeshRepo_GetByInviteCode_ExpiredReturnsError(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)

	subnet, _ := r.NextAvailableSubnet(context.Background())
	past := time.Now().Add(-1 * time.Hour)
	mesh := &models.MeshNetwork{
		Name:            "Expired Mesh",
		OwnerID:         ownerID,
		Subnet:          subnet,
		MaxMembers:      5,
		InviteExpiresAt: &past,
	}
	if err := r.Create(context.Background(), mesh); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })

	_, err := r.GetByInviteCode(context.Background(), mesh.InviteCode)
	if err == nil {
		t.Fatal("expected error for expired invite code, got nil")
	}
}

func TestMeshRepo_NextAvailableSubnet_NoCollision(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)

	m1 := insertTestMesh(t, r, ownerID)
	m2 := insertTestMesh(t, r, ownerID)

	if m1.Subnet == m2.Subnet {
		t.Errorf("expected different subnets for two meshes, both got %q", m1.Subnet)
	}
}

func TestMeshRepo_AddMember_AssignsIP(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	mesh := insertTestMesh(t, r, ownerID)

	member := &models.MeshMember{UserID: ownerID}
	if err := r.AddMember(context.Background(), mesh.ID, member); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if member.MeshIP == "" {
		t.Fatal("expected non-empty MeshIP after AddMember")
	}
	if member.MeshIP == "10.200.0.1" {
		t.Error("MeshIP must not use .1 (reserved as gateway)")
	}
}

func TestMeshRepo_AddMember_NoDuplicateIPs_Concurrent(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	mesh := insertTestMesh(t, r, ownerID)

	const goroutines = 5
	users := make([]uuid.UUID, goroutines)
	for i := range users {
		users[i] = insertTestUser(t, pool)
	}

	errs := make([]error, goroutines)
	ips := make([]string, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			m := &models.MeshMember{UserID: users[i]}
			errs[i] = r.AddMember(context.Background(), mesh.ID, m)
			ips[i] = m.MeshIP
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: AddMember error: %v", i, err)
		}
	}

	seen := make(map[string]bool)
	for i, ip := range ips {
		if errs[i] != nil {
			continue
		}
		if seen[ip] {
			t.Errorf("duplicate mesh IP assigned: %q", ip)
		}
		seen[ip] = true
	}
}

func TestMeshRepo_CountMembers(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	mesh := insertTestMesh(t, r, ownerID)

	member := &models.MeshMember{UserID: ownerID}
	if err := r.AddMember(context.Background(), mesh.ID, member); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	count, err := r.CountMembers(context.Background(), mesh.ID)
	if err != nil {
		t.Fatalf("CountMembers: %v", err)
	}
	if count != 1 {
		t.Errorf("CountMembers = %d; want 1", count)
	}
}

func TestMeshRepo_RemoveMember(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	mesh := insertTestMesh(t, r, ownerID)

	member := &models.MeshMember{UserID: ownerID}
	if err := r.AddMember(context.Background(), mesh.ID, member); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := r.RemoveMember(context.Background(), mesh.ID, ownerID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	count, _ := r.CountMembers(context.Background(), mesh.ID)
	if count != 0 {
		t.Errorf("expected 0 members after RemoveMember, got %d", count)
	}
}

func TestMeshRepo_RegenerateInviteCode(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	mesh := insertTestMesh(t, r, ownerID)

	originalCode := mesh.InviteCode

	newCode, expiresAt, err := r.RegenerateInviteCode(context.Background(), mesh.ID, nil)
	if err != nil {
		t.Fatalf("RegenerateInviteCode: %v", err)
	}
	if newCode == "" {
		t.Fatal("expected non-empty new invite code")
	}
	if newCode == originalCode {
		t.Error("expected new code to differ from original")
	}
	if expiresAt != nil {
		t.Errorf("expected nil expiresAt when none provided, got %v", expiresAt)
	}
	if _, err := uuid.Parse(newCode); err != nil {
		t.Fatalf("new invite code %q is not a valid UUID: %v", newCode, err)
	}

	// Verify the old code no longer works.
	_, err = r.GetByInviteCode(context.Background(), originalCode)
	if err == nil {
		t.Error("old invite code should no longer be valid after regeneration")
	}

	// Verify the new code works.
	got, err := r.GetByInviteCode(context.Background(), newCode)
	if err != nil {
		t.Fatalf("new invite code not found: %v", err)
	}
	if got.ID != mesh.ID {
		t.Errorf("GetByInviteCode returned mesh %v; want %v", got.ID, mesh.ID)
	}
}

func TestMeshRepo_RegenerateInviteCode_WithExpiry(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	mesh := insertTestMesh(t, r, ownerID)

	expiry := time.Now().UTC().Add(24 * time.Hour)
	newCode, returnedExpiry, err := r.RegenerateInviteCode(context.Background(), mesh.ID, &expiry)
	if err != nil {
		t.Fatalf("RegenerateInviteCode with expiry: %v", err)
	}
	if returnedExpiry == nil {
		t.Fatal("expected non-nil expiresAt")
	}
	if returnedExpiry.Before(time.Now()) {
		t.Errorf("expiresAt %v is in the past", returnedExpiry)
	}

	// New code should be reachable (not yet expired).
	_, err = r.GetByInviteCode(context.Background(), newCode)
	if err != nil {
		t.Fatalf("new code should be valid before expiry: %v", err)
	}
}

func TestMeshRepo_ListByUser(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)
	otherID := insertTestUser(t, pool)

	mesh := insertTestMesh(t, r, ownerID)
	_ = insertTestMesh(t, r, otherID) // a mesh the owner did not create

	meshes, err := r.ListByUser(context.Background(), ownerID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}

	found := false
	for _, m := range meshes {
		if m.ID == mesh.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("owner's mesh not found in ListByUser result")
	}
}

func TestMeshRepo_DeleteStaleSessions(t *testing.T) {
	pool := testPool(t)
	r := repo.NewMeshRepo(pool)
	ownerID := insertTestUser(t, pool)

	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{
		Name:       "Stale Session",
		OwnerID:    ownerID,
		Subnet:     subnet,
		MaxMembers: 5,
		IsSession:  true,
	}
	if err := r.CreateSession(context.Background(), mesh); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// Back-date updated_at so it falls outside the stale window.
	_, err := pool.Exec(context.Background(),
		`UPDATE mesh_networks SET updated_at = NOW() - INTERVAL '3 hours' WHERE id = $1`, mesh.ID)
	if err != nil {
		t.Fatalf("back-date updated_at: %v", err)
	}

	deleted, err := r.DeleteStaleSessions(context.Background(), 2*time.Hour)
	if err != nil {
		t.Fatalf("DeleteStaleSessions: %v", err)
	}
	if deleted == 0 {
		t.Error("expected at least 1 stale session deleted")
	}

	// Verify it's gone.
	_, err = r.GetByID(context.Background(), mesh.ID)
	if err == nil {
		t.Error("stale session mesh should have been deleted")
	}
}
