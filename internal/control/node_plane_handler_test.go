package control_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/desiredstate"
	"github.com/goastian/midori-vpn-core/internal/fleetauth"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/nodeplane"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

func TestNodePlaneEnrollmentHeartbeatReplayAndRevocation(t *testing.T) {
	pool := handlerTestPool(t)
	multicluster := repo.NewMulticlusterRepo(pool)
	cluster := &models.Cluster{
		Name: "handler-" + uuid.NewString(), Region: "test", State: models.ClusterStateInactive,
	}
	if err := multicluster.CreateCluster(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	node := &models.CoreNode{
		ClusterID: cluster.ID, Name: "node-" + uuid.NewString(),
		ManagementHost: uuid.NewString() + ".nodes.test.invalid", State: models.ClusterStateEnrolling,
	}
	if err := multicluster.CreateNode(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})
	token, err := multicluster.IssueEnrollmentToken(context.Background(), node.ID, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fleetauth.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "node"), node.ID)
	if err != nil {
		t.Fatal(err)
	}
	handler := control.NewNodePlaneHandler(pool, &config.Config{AppEnv: "development"})

	enrollmentBody := marshalNodeRequest(t, nodeplane.EnrollmentRequest{
		NodeID: node.ID.String(), PublicKey: identity.EncodedPublicKey(),
	})
	enrollment := signedNodeRequest(t, identity, nodeplane.EnrollmentPath, enrollmentBody)
	enrollment.Header.Set("Authorization", "Bearer "+token.Token)
	recorder := httptest.NewRecorder()
	handler.Enroll(recorder, enrollment)
	if recorder.Code != http.StatusCreated || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("enrollment status/cache = %d/%q; body=%s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}

	replay := replayNodeRequest(enrollment, enrollmentBody)
	replay.Header.Set("Authorization", "Bearer "+token.Token)
	recorder = httptest.NewRecorder()
	handler.Enroll(recorder, replay)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("enrollment replay status = %d; want 401", recorder.Code)
	}

	heartbeatBody := marshalNodeRequest(t, nodeplane.HeartbeatRequest{
		SchemaVersion: nodeplane.SchemaVersion,
		CoreVersion:   "2.0.0",
		HealthStatus:  "healthy",
		CurrentPeers:  2,
		MaxPeers:      100,
		TransportStates: map[string]models.NodeTransportState{
			"wireguard": {Status: "healthy", Certified: false},
		},
		ReportedAt: time.Now().UTC(),
	})
	heartbeat := signedNodeRequest(t, identity, nodeplane.HeartbeatPath, heartbeatBody)
	recorder = httptest.NewRecorder()
	handler.Heartbeat(recorder, heartbeat)
	if recorder.Code != http.StatusOK {
		t.Fatalf("heartbeat status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var observationCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM node_observations WHERE node_id = $1`, node.ID).Scan(&observationCount); err != nil {
		t.Fatal(err)
	}
	if observationCount != 1 {
		t.Fatalf("observation count = %d; want 1", observationCount)
	}

	recorder = httptest.NewRecorder()
	handler.Heartbeat(recorder, replayNodeRequest(heartbeat, heartbeatBody))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("heartbeat replay status = %d; want 401", recorder.Code)
	}
	if err := multicluster.RevokeNode(context.Background(), node.ID); err != nil {
		t.Fatal(err)
	}
	revokedHeartbeat := signedNodeRequest(t, identity, nodeplane.HeartbeatPath, heartbeatBody)
	recorder = httptest.NewRecorder()
	handler.Heartbeat(recorder, revokedHeartbeat)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("revoked heartbeat status = %d; want 401", recorder.Code)
	}
}

func TestAdminUpdateCoreNodeOnlyBeforeEnrollment(t *testing.T) {
	pool := handlerTestPool(t)
	fleet := repo.NewMulticlusterRepo(pool)
	cluster := &models.Cluster{Name: "update-" + uuid.NewString(), Region: "test", State: models.ClusterStateInactive}
	if err := fleet.CreateCluster(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	node := &models.CoreNode{
		ClusterID: cluster.ID, Name: "update-" + uuid.NewString()[:8],
		ManagementHost: uuid.NewString() + ".nodes.test.invalid", State: models.ClusterStateEnrolling,
	}
	if err := fleet.CreateNode(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM node_enrollment_tokens WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM core_nodes WHERE id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})
	handler := control.NewHandler(pool, &config.Config{AppEnv: "development"})
	requestFor := func(host string) *http.Request {
		body := marshalNodeRequest(t, map[string]string{"management_host": host})
		request := httptest.NewRequest(http.MethodPatch, "https://control.test/api/v1/admin/nodes/"+node.ID.String(), bytes.NewReader(body))
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("nodeID", node.ID.String())
		ctx := context.WithValue(request.Context(), chi.RouteCtxKey, routeContext)
		ctx = context.WithValue(ctx, auth.UserCtxKey, &models.User{ID: uuid.New(), Groups: []string{"vpn-admins"}})
		return request.WithContext(ctx)
	}
	recorder := httptest.NewRecorder()
	handler.AdminUpdateCoreNode(recorder, requestFor("10.254.240.2"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("management update status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data models.CoreNode `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Data.ManagementHost != "10.254.240.2" {
		t.Fatalf("management host = %q", response.Data.ManagementHost)
	}
	token, err := fleet.IssueEnrollmentToken(context.Background(), node.ID, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleet.EnrollNode(context.Background(), node.ID, token.Token, publicKey); err != nil {
		t.Fatal(err)
	}
	recorder = httptest.NewRecorder()
	handler.AdminUpdateCoreNode(recorder, requestFor("10.254.240.3"))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "node_management_host_immutable") {
		t.Fatalf("enrolled management update = %d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestDesiredStateIssuanceAndNodeScopedFetch(t *testing.T) {
	pool := handlerTestPool(t)
	multicluster := repo.NewMulticlusterRepo(pool)
	cluster := &models.Cluster{Name: "desired-" + uuid.NewString(), Region: "test", State: models.ClusterStateInactive}
	if err := multicluster.CreateCluster(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	node := &models.CoreNode{
		ClusterID: cluster.ID, Name: "desired-" + uuid.NewString()[:8],
		ManagementHost: uuid.NewString() + ".nodes.test.invalid", State: models.ClusterStateEnrolling,
	}
	if err := multicluster.CreateNode(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	identity, err := fleetauth.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "node"), node.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, err := multicluster.IssueEnrollmentToken(context.Background(), node.ID, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := multicluster.EnrollNode(context.Background(), node.ID, token.Token, identity.PublicKey()); err != nil {
		t.Fatalf("enroll fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			DELETE FROM audit_logs
			WHERE action = 'system.core-node.desired-state.renew'
			  AND metadata->>'node_id' = $1`, node.ID.String())
		_, _ = pool.Exec(context.Background(), `DELETE FROM desired_revisions WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM node_enrollment_tokens WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM core_nodes WHERE id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := uuid.NewString()
	cfg := &config.Config{
		AppEnv: "development", PublicBaseURL: "https://control.test",
		ControlNodeID: keyID, ControlNodePrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
		NodeAuthorizedKeys: keyID + "=" + base64.RawURLEncoding.EncodeToString(publicKey),
	}
	adminHandler := control.NewHandler(pool, cfg)
	requestBody := map[string]any{
		"expected_previous_revision": nil, "expires_in_seconds": 600,
		"minimum_core_version": "2.0.0",
		"public_endpoints":     []map[string]any{{"name": "wg", "host": "vpn.test", "port": 51820}},
		"capacity":             map[string]any{"max_peers": 100},
		"transports": []map[string]any{{
			"protocol": "wireguard", "enabled": true, "priority": 10,
			"endpoint": "wg", "secret_references": []string{},
		}},
		"secret_references": []any{},
	}
	body := marshalNodeRequest(t, requestBody)
	adminRequest := httptest.NewRequest(http.MethodPost, "https://control.test/api/v1/admin/nodes/"+node.ID.String()+"/desired-state", bytes.NewReader(body))
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("nodeID", node.ID.String())
	ctx := context.WithValue(adminRequest.Context(), chi.RouteCtxKey, routeContext)
	ctx = context.WithValue(ctx, auth.UserCtxKey, &models.User{ID: uuid.New(), Groups: []string{"vpn-admins"}})
	adminRequest = adminRequest.WithContext(ctx)
	adminRecorder := httptest.NewRecorder()
	adminHandler.AdminCreateDesiredState(adminRecorder, adminRequest)
	if adminRecorder.Code != http.StatusCreated || adminRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("issue desired state = %d/%q body=%s", adminRecorder.Code, adminRecorder.Header().Get("Cache-Control"), adminRecorder.Body.String())
	}
	staleRequest := httptest.NewRequest(http.MethodPost, adminRequest.URL.String(), bytes.NewReader(body)).WithContext(ctx)
	staleRecorder := httptest.NewRecorder()
	adminHandler.AdminCreateDesiredState(staleRecorder, staleRequest)
	if staleRecorder.Code != http.StatusConflict {
		t.Fatalf("stale desired state issuance = %d body=%s", staleRecorder.Code, staleRecorder.Body.String())
	}

	nodeHandler := control.NewNodePlaneHandler(pool, &config.Config{AppEnv: "development"})
	fetch := httptest.NewRequest(http.MethodGet, "https://control.test"+nodeplane.DesiredStatePath, nil)
	if err := identity.Sign(fetch, nil); err != nil {
		t.Fatal(err)
	}
	fetchRecorder := httptest.NewRecorder()
	nodeHandler.DesiredState(fetchRecorder, fetch)
	if fetchRecorder.Code != http.StatusOK || fetchRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("fetch desired state = %d/%q body=%s", fetchRecorder.Code, fetchRecorder.Header().Get("Cache-Control"), fetchRecorder.Body.String())
	}
	var envelope struct {
		Data desiredstate.SignedBundle `json:"data"`
	}
	if err := json.NewDecoder(fetchRecorder.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	verifier, err := desiredstate.NewVerifier(keyID + "=" + base64.RawURLEncoding.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(envelope.Data, node.ID, "2.0.0", time.Now().UTC(), false); err != nil {
		t.Fatalf("verify fetched desired state: %v", err)
	}
	if envelope.Data.Bundle.Revision != 1 || envelope.Data.Bundle.ClusterID != cluster.ID {
		t.Fatalf("unexpected desired state: %#v", envelope.Data.Bundle)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE clusters SET state = 'active' WHERE id = $1`, cluster.ID); err != nil {
		t.Fatalf("activate desired-state renewal fixture: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE core_nodes SET state = 'active' WHERE id = $1`, node.ID); err != nil {
		t.Fatalf("activate desired-state renewal node fixture: %v", err)
	}
	renewer, err := control.NewDesiredStateRenewer(pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := renewer.RunOnce(context.Background(), time.Now().UTC())
	if report.Candidates != 1 || report.Renewed != 1 || report.Conflicts != 0 || report.Errors != 0 {
		t.Fatalf("desired state renewal report = %#v", report)
	}
	latest, err := multicluster.LatestDesiredRevision(context.Background(), node.ID)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := desiredstate.DecodeStored(latest.Payload, latest.PayloadSHA256, latest.Signature, latest.SigningKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(renewed, node.ID, "2.0.0", time.Now().UTC(), false); err != nil {
		t.Fatalf("verify renewed desired state: %v", err)
	}
	if renewed.Bundle.Revision != 2 || renewed.Bundle.PreviousRevision == nil || *renewed.Bundle.PreviousRevision != 1 ||
		!renewed.Bundle.ExpiresAt.After(time.Now().UTC().Add(23*time.Hour)) {
		t.Fatalf("unexpected renewed desired state: %#v", renewed.Bundle)
	}
	var renewalAudits int
	if err := pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM audit_logs
		WHERE action = 'system.core-node.desired-state.renew'
		  AND metadata->>'node_id' = $1`, node.ID.String()).Scan(&renewalAudits); err != nil {
		t.Fatal(err)
	}
	if renewalAudits != 1 {
		t.Fatalf("renewal audit count = %d, want 1", renewalAudits)
	}

	replayRecorder := httptest.NewRecorder()
	nodeHandler.DesiredState(replayRecorder, replayNodeRequest(fetch, nil))
	if replayRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("desired state replay = %d", replayRecorder.Code)
	}
}

func TestNodePlaneEnrollmentRejectsTamperedBody(t *testing.T) {
	pool := handlerTestPool(t)
	handler := control.NewNodePlaneHandler(pool, &config.Config{AppEnv: "development"})
	nodeID := uuid.New()
	identity, err := fleetauth.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "node"), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	body := marshalNodeRequest(t, nodeplane.EnrollmentRequest{NodeID: nodeID.String(), PublicKey: identity.EncodedPublicKey()})
	request := signedNodeRequest(t, identity, nodeplane.EnrollmentPath, body)
	request.Body = io.NopCloser(bytes.NewReader(append(body, ' ')))
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 43))
	recorder := httptest.NewRecorder()
	handler.Enroll(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("tampered enrollment status = %d; want 401", recorder.Code)
	}
}

func marshalNodeRequest(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func signedNodeRequest(t *testing.T, identity *fleetauth.Identity, path string, body []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://control.test"+path, bytes.NewReader(body))
	if err := identity.Sign(request, body); err != nil {
		t.Fatal(err)
	}
	return request
}

func replayNodeRequest(original *http.Request, body []byte) *http.Request {
	replay := httptest.NewRequest(original.Method, original.URL.String(), bytes.NewReader(body))
	replay.Header = original.Header.Clone()
	return replay
}
