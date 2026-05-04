package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/db"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

// ─── test helpers ────────────────────────────────────────────────────────────

func handlerTestPool(t *testing.T) *pgxpool.Pool {
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

func insertUser(t *testing.T, pool *pgxpool.Pool) *models.User {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (authentik_uid, email, display_name)
		 VALUES ($1, $2, $3)
		 RETURNING id`,
		uuid.New().String(), uuid.New().String()+"@test.invalid", "Handler Test User",
	).Scan(&id)
	if err != nil {
		t.Fatalf("insertUser: %v", err)
	}
	u := &models.User{ID: id, Email: "test@test.invalid", Groups: []string{}}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return u
}

// withUser injects a *models.User into the request context so that
// auth.GetUser(r) works without a real JWT middleware.
func withUser(r *http.Request, u *models.User) *http.Request {
	ctx := context.WithValue(r.Context(), auth.UserCtxKey, u)
	return r.WithContext(ctx)
}

// withChiParam attaches chi URL params to the request context.
func withChiParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func jsonBody(t *testing.T, v interface{}) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return bytes.NewBuffer(b)
}

// ─── CreateMesh ──────────────────────────────────────────────────────────────

func TestCreateMesh_Disabled(t *testing.T) {
	pool := handlerTestPool(t)
	u := insertUser(t, pool)

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(httptest.NewRequest(http.MethodPost, "/mesh", jsonBody(t, map[string]interface{}{
		"name":        "Test Network",
		"max_members": 5,
	})), u)
	w := httptest.NewRecorder()
	h.CreateMesh(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateMesh_MissingNameStillDisabled(t *testing.T) {
	pool := handlerTestPool(t)
	u := insertUser(t, pool)

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(httptest.NewRequest(http.MethodPost, "/mesh", jsonBody(t, map[string]interface{}{
		"max_members": 5,
	})), u)
	w := httptest.NewRecorder()
	h.CreateMesh(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", w.Code)
	}
}

// ─── JoinMesh ────────────────────────────────────────────────────────────────

func TestJoinMesh_Disabled(t *testing.T) {
	pool := handlerTestPool(t)
	owner := insertUser(t, pool)
	joiner := insertUser(t, pool)

	// Create mesh as owner via repo to have control over state.
	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Join Test", OwnerID: owner.ID, Subnet: subnet, MaxMembers: 10}
	if err := r.Create(context.Background(), mesh); err != nil {
		t.Fatalf("Create mesh: %v", err)
	}
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })

	// Owner must be first member.
	ownerMember := &models.MeshMember{UserID: owner.ID}
	r.AddMember(context.Background(), mesh.ID, ownerMember)

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(httptest.NewRequest(http.MethodPost, "/mesh/join", jsonBody(t, map[string]interface{}{
		"invite_code": mesh.InviteCode,
	})), joiner)
	w := httptest.NewRecorder()
	h.JoinMesh(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestJoinMesh_InvalidCodeStillDisabled(t *testing.T) {
	pool := handlerTestPool(t)
	u := insertUser(t, pool)

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(httptest.NewRequest(http.MethodPost, "/mesh/join", jsonBody(t, map[string]interface{}{
		"invite_code": "not-a-uuid",
	})), u)
	w := httptest.NewRecorder()
	h.JoinMesh(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", w.Code)
	}
}

func TestJoinMesh_AlreadyMemberStillDisabled(t *testing.T) {
	pool := handlerTestPool(t)
	owner := insertUser(t, pool)

	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Duplicate Join", OwnerID: owner.ID, Subnet: subnet, MaxMembers: 10}
	r.Create(context.Background(), mesh)
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: owner.ID})

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(httptest.NewRequest(http.MethodPost, "/mesh/join", jsonBody(t, map[string]interface{}{
		"invite_code": mesh.InviteCode,
	})), owner)
	w := httptest.NewRecorder()
	h.JoinMesh(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", w.Code)
	}
}

func TestJoinMesh_MeshFullStillDisabled(t *testing.T) {
	pool := handlerTestPool(t)
	owner := insertUser(t, pool)
	extra := insertUser(t, pool)

	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Full Mesh", OwnerID: owner.ID, Subnet: subnet, MaxMembers: 1}
	r.Create(context.Background(), mesh)
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: owner.ID})

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(httptest.NewRequest(http.MethodPost, "/mesh/join", jsonBody(t, map[string]interface{}{
		"invite_code": mesh.InviteCode,
	})), extra)
	w := httptest.NewRecorder()
	h.JoinMesh(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", w.Code)
	}
}

// ─── RegenerateInvite ─────────────────────────────────────────────────────────

func TestRegenerateInvite_Disabled(t *testing.T) {
	pool := handlerTestPool(t)
	owner := insertUser(t, pool)

	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Invite Regen", OwnerID: owner.ID, Subnet: subnet, MaxMembers: 10}
	r.Create(context.Background(), mesh)
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: owner.ID})

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(
		withChiParam(httptest.NewRequest(http.MethodPost, "/mesh/"+mesh.ID.String()+"/invite", jsonBody(t, map[string]interface{}{})), "id", mesh.ID.String()),
		owner,
	)
	w := httptest.NewRecorder()
	h.RegenerateInvite(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegenerateInvite_WithExpiryStillDisabled(t *testing.T) {
	pool := handlerTestPool(t)
	owner := insertUser(t, pool)

	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Expiry Regen", OwnerID: owner.ID, Subnet: subnet, MaxMembers: 10}
	r.Create(context.Background(), mesh)
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(
		withChiParam(httptest.NewRequest(http.MethodPost, "/mesh/"+mesh.ID.String()+"/invite",
			jsonBody(t, map[string]interface{}{"expires_in_hours": 24})), "id", mesh.ID.String()),
		owner,
	)
	w := httptest.NewRecorder()
	h.RegenerateInvite(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegenerateInvite_NonOwnerStillDisabled(t *testing.T) {
	pool := handlerTestPool(t)
	owner := insertUser(t, pool)
	nonOwner := insertUser(t, pool)

	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Forbidden Regen", OwnerID: owner.ID, Subnet: subnet, MaxMembers: 10}
	r.Create(context.Background(), mesh)
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: owner.ID})
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: nonOwner.ID})

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(
		withChiParam(httptest.NewRequest(http.MethodPost, "/mesh/"+mesh.ID.String()+"/invite",
			jsonBody(t, map[string]interface{}{})), "id", mesh.ID.String()),
		nonOwner,
	)
	w := httptest.NewRecorder()
	h.RegenerateInvite(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegenerateInvite_InvalidMeshIDStillDisabled(t *testing.T) {
	pool := handlerTestPool(t)
	u := insertUser(t, pool)

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(
		withChiParam(httptest.NewRequest(http.MethodPost, "/mesh/bad-id/invite",
			jsonBody(t, map[string]interface{}{})), "id", "bad-id"),
		u,
	)
	w := httptest.NewRecorder()
	h.RegenerateInvite(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d", w.Code)
	}
}

// ─── LeaveMesh ───────────────────────────────────────────────────────────────

func TestLeaveMesh_NonOwnerLeaves(t *testing.T) {
	pool := handlerTestPool(t)
	owner := insertUser(t, pool)
	member := insertUser(t, pool)

	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Leave Test", OwnerID: owner.ID, Subnet: subnet, MaxMembers: 10}
	r.Create(context.Background(), mesh)
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: owner.ID})
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: member.ID})

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(
		withChiParam(httptest.NewRequest(http.MethodDelete, "/mesh/"+mesh.ID.String(), nil), "id", mesh.ID.String()),
		member,
	)
	w := httptest.NewRecorder()
	h.LeaveMesh(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Member should be gone.
	count, _ := r.CountMembers(context.Background(), mesh.ID)
	if count != 1 {
		t.Errorf("expected 1 remaining member after leave, got %d", count)
	}
}

func TestLeaveMesh_OwnerDeletesMesh(t *testing.T) {
	pool := handlerTestPool(t)
	owner := insertUser(t, pool)

	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Owner Delete", OwnerID: owner.ID, Subnet: subnet, MaxMembers: 10}
	r.Create(context.Background(), mesh)
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: owner.ID})

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(
		withChiParam(httptest.NewRequest(http.MethodDelete, "/mesh/"+mesh.ID.String(), nil), "id", mesh.ID.String()),
		owner,
	)
	w := httptest.NewRecorder()
	h.LeaveMesh(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Mesh should be gone.
	_, err := r.GetByID(context.Background(), mesh.ID)
	if err == nil {
		t.Error("mesh should have been deleted when owner leaves")
	}
}

// ─── NodeStatus ──────────────────────────────────────────────────────────────

func TestNodeStatus_Inactive(t *testing.T) {
	pool := handlerTestPool(t)
	u := insertUser(t, pool)

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(httptest.NewRequest(http.MethodGet, "/mesh/node", nil), u)
	w := httptest.NewRecorder()
	h.NodeStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var status struct {
		Active bool `json:"active"`
	}
	json.NewDecoder(w.Body).Decode(&status)
	if status.Active {
		t.Error("expected active=false for user with no meshes")
	}
}

func TestNodeStatus_Active(t *testing.T) {
	pool := handlerTestPool(t)
	u := insertUser(t, pool)

	r := repo.NewMeshRepo(pool)
	subnet, _ := r.NextAvailableSubnet(context.Background())
	mesh := &models.MeshNetwork{Name: "Node Mesh", OwnerID: u.ID, Subnet: subnet, MaxMembers: 10}
	r.Create(context.Background(), mesh)
	t.Cleanup(func() { r.Delete(context.Background(), mesh.ID) })
	r.AddMember(context.Background(), mesh.ID, &models.MeshMember{UserID: u.ID})

	h := control.NewMeshHandler(pool, nil, nil)
	req := withUser(httptest.NewRequest(http.MethodGet, "/mesh/node", nil), u)
	w := httptest.NewRecorder()
	h.NodeStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var status struct {
		Active bool   `json:"active"`
		MeshIP string `json:"mesh_ip"`
	}
	json.NewDecoder(w.Body).Decode(&status)
	if !status.Active {
		t.Error("expected active=true for user with a mesh")
	}
	if status.MeshIP == "" {
		t.Error("expected mesh_ip to be set")
	}
}
