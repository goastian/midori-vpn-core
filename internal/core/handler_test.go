package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

type fakePeerManager struct {
	addIP      string
	addCreated bool
	addErr     error
	removeErr  error
	list       []wg.PeerInfo
	listErr    error
	stats      *wg.PeerInfo
	statsErr   error
	operation  string
}

func (f *fakePeerManager) AddPeerWithPSK(_, operationID string, _ int, _ string) (string, bool, error) {
	f.operation = operationID
	return f.addIP, f.addCreated, f.addErr
}

func (f *fakePeerManager) RemovePeer(_, operationID string) error {
	f.operation = operationID
	return f.removeErr
}

func (f *fakePeerManager) UpdatePeer(string, int) error { return nil }
func (f *fakePeerManager) PeerStats(string) (*wg.PeerInfo, error) {
	return f.stats, f.statsErr
}
func (f *fakePeerManager) ListPeers() ([]wg.PeerInfo, error) { return f.list, f.listErr }
func (f *fakePeerManager) ServerStats() (*wg.ServerStatsResponse, error) {
	return &wg.ServerStatsResponse{}, nil
}

func peerRequest(t *testing.T, method, target string, body any) *http.Request {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	return httptest.NewRequest(method, target, &encoded)
}

func withPeerKey(request *http.Request, publicKey string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("pubkey", publicKey)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func responseCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var response struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response.Code
}

func TestAddPeerReturnsCreatedThenIdempotentStatus(t *testing.T) {
	operationID := uuid.NewString()
	manager := &fakePeerManager{addIP: "10.77.0.2/32", addCreated: true}
	handler := newHandler(&config.Config{Endpoint: "vpn.test", WGPort: 51820}, manager)
	requestBody := map[string]any{
		"public_key": testCoreKey(1), "preshared_key": testCoreKey(2),
		"keepalive": 25, "operation_id": operationID,
	}

	createdRecorder := httptest.NewRecorder()
	handler.AddPeer(createdRecorder, peerRequest(t, http.MethodPost, "/api/v1/peers", requestBody))
	if createdRecorder.Code != http.StatusCreated || manager.operation != operationID {
		t.Fatalf("created response=%d operation=%q body=%s", createdRecorder.Code, manager.operation, createdRecorder.Body.String())
	}
	var createdResponse struct {
		Data AddPeerResponse `json:"data"`
	}
	if err := json.NewDecoder(createdRecorder.Body).Decode(&createdResponse); err != nil {
		t.Fatal(err)
	}
	if createdResponse.Data.OperationID != operationID || createdResponse.Data.AllowedIP != "10.77.0.2/32" {
		t.Fatalf("unexpected response: %#v", createdResponse.Data)
	}

	manager.addCreated = false
	replayRecorder := httptest.NewRecorder()
	handler.AddPeer(replayRecorder, peerRequest(t, http.MethodPost, "/api/v1/peers", requestBody))
	if replayRecorder.Code != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", replayRecorder.Code, replayRecorder.Body.String())
	}
}

func TestPeerOperationConflictAndUnavailableStateAreExplicit(t *testing.T) {
	manager := &fakePeerManager{addErr: wg.ErrPeerOperationConflict}
	handler := newHandler(&config.Config{}, manager)
	requestBody := map[string]any{"public_key": testCoreKey(3), "keepalive": 25, "operation_id": uuid.NewString()}
	recorder := httptest.NewRecorder()
	handler.AddPeer(recorder, peerRequest(t, http.MethodPost, "/api/v1/peers", requestBody))
	if recorder.Code != http.StatusConflict || responseCode(t, recorder) != "peer_operation_conflict" {
		t.Fatalf("conflict response status=%d", recorder.Code)
	}

	manager.listErr = errors.New("netlink unavailable")
	listRecorder := httptest.NewRecorder()
	handler.ListPeers(listRecorder, peerRequest(t, http.MethodGet, "/api/v1/peers", nil))
	if listRecorder.Code != http.StatusServiceUnavailable || responseCode(t, listRecorder) != "core_peer_state_unavailable" {
		t.Fatalf("list failure response status=%d", listRecorder.Code)
	}
}

func TestRemovePeerRequiresAndForwardsExpectedOperation(t *testing.T) {
	manager := &fakePeerManager{}
	handler := newHandler(&config.Config{}, manager)
	publicKey := testCoreKey(4)

	missingRecorder := httptest.NewRecorder()
	handler.RemovePeer(missingRecorder, withPeerKey(peerRequest(t, http.MethodDelete, "/api/v1/peers/key", nil), publicKey))
	if missingRecorder.Code != http.StatusBadRequest {
		t.Fatalf("missing expected operation status=%d", missingRecorder.Code)
	}

	operationID := uuid.NewString()
	exactRecorder := httptest.NewRecorder()
	exactRequest := withPeerKey(peerRequest(t, http.MethodDelete, "/api/v1/peers/key?expected_operation_id="+operationID, nil), publicKey)
	handler.RemovePeer(exactRecorder, exactRequest)
	if exactRecorder.Code != http.StatusOK || manager.operation != operationID {
		t.Fatalf("exact remove status=%d operation=%q", exactRecorder.Code, manager.operation)
	}

	manager.removeErr = wg.ErrPeerOperationConflict
	conflictRecorder := httptest.NewRecorder()
	handler.RemovePeer(conflictRecorder, exactRequest)
	if conflictRecorder.Code != http.StatusConflict || responseCode(t, conflictRecorder) != "peer_operation_conflict" {
		t.Fatalf("remove conflict status=%d", conflictRecorder.Code)
	}
}

func testCoreKey(fill byte) string {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = fill
	}
	return base64.StdEncoding.EncodeToString(raw)
}
