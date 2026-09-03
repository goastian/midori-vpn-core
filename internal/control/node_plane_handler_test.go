package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
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
