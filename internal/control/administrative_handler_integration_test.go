package control_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/models"
)

func responseStatus(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var response struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	return response.Data.Status
}

func responseErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var response struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return response.Code
}

func TestDisconnectReturnsAcceptedWithoutHidingActiveAccess(t *testing.T) {
	handler, user, _, _, activePeerID := insertDeviceHandlerFixture(t)
	request := withUser(
		withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/control/connections/"+activePeerID.String(), nil), "id", activePeerID.String()),
		user,
	)
	recorder := httptest.NewRecorder()
	handler.Disconnect(recorder, request)
	if recorder.Code != http.StatusAccepted || responseStatus(t, recorder) != "disconnect_pending" || recorder.Header().Get("Retry-After") != "5" {
		t.Fatalf("disconnect response: status=%d body=%s retry=%q", recorder.Code, recorder.Body.String(), recorder.Header().Get("Retry-After"))
	}
	pool := handlerTestPool(t)
	var active bool
	var state models.PeerOperationState
	if err := pool.QueryRow(context.Background(), `
		SELECT peer.is_active, operation.state
		FROM peers peer
		JOIN peer_operations operation ON operation.previous_peer_id = peer.id
		WHERE peer.id = $1 AND operation.action = 'disconnect'
		ORDER BY operation.created_at DESC LIMIT 1`, activePeerID).Scan(&active, &state); err != nil {
		t.Fatalf("load pending disconnect: %v", err)
	}
	if !active || state != models.PeerOperationPending {
		t.Fatalf("pending disconnect hid access or lost intent: active=%t state=%s", active, state)
	}
}

func TestDisconnectCompletesAfterCallerCancellation(t *testing.T) {
	handler, user, _, _, activePeerID := insertDeviceHandlerFixture(t)
	pool := handlerTestPool(t)
	operationID := uuid.New()
	deleteObserved := make(chan struct{}, 1)
	requestContext, cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()

	coreServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			cancelRequest()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":   true,
				"data": map[string]string{"operation_id": operationID.String()},
			})
		case r.Method == http.MethodDelete:
			deleteObserved <- struct{}{}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer coreServer.Close()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Control signing identity: %v", err)
	}
	if err := control.InitCoreSigningIdentity("disconnect-context-test", base64.RawURLEncoding.EncodeToString(privateKey)); err != nil {
		t.Fatalf("initialize Control signing identity: %v", err)
	}
	control.InitCoreClient(false, true, "")
	t.Cleanup(func() {
		control.CloseCoreClient()
		control.InitCoreClient(false, false, "")
	})

	var serverID uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		SELECT server_id FROM peers WHERE id = $1`, activePeerID).Scan(&serverID); err != nil {
		t.Fatalf("load disconnect server: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE vpn_servers SET host = $2 WHERE id = $1`, serverID, coreServer.URL); err != nil {
		t.Fatalf("point disconnect server at fixture Core: %v", err)
	}

	request := withUser(
		withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/control/connections/"+activePeerID.String(), nil).WithContext(requestContext), "id", activePeerID.String()),
		user,
	)
	recorder := httptest.NewRecorder()
	handler.Disconnect(recorder, request)
	if recorder.Code != http.StatusOK || responseStatus(t, recorder) != "disconnected" {
		t.Fatalf("disconnect response after cancellation: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	select {
	case <-deleteObserved:
	default:
		t.Fatal("Core did not observe the exact disconnect after caller cancellation")
	}

	var active bool
	var state models.PeerOperationState
	if err := pool.QueryRow(context.Background(), `
		SELECT peer.is_active, operation.state
		FROM peers peer
		JOIN peer_operations operation ON operation.previous_peer_id = peer.id
		WHERE peer.id = $1 AND operation.action = 'disconnect'
		ORDER BY operation.created_at DESC LIMIT 1`, activePeerID).Scan(&active, &state); err != nil {
		t.Fatalf("load completed disconnect: %v", err)
	}
	if active || state != models.PeerOperationCompleted {
		t.Fatalf("disconnect did not converge: active=%t state=%s", active, state)
	}
}

func TestBanBlocksFirstAndReportsPendingCleanup(t *testing.T) {
	handler, user, _, _, activePeerID := insertDeviceHandlerFixture(t)
	admin := &models.User{ID: uuid.New(), Groups: []string{"midorivpn-admins"}}
	request := withUser(
		withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+user.ID.String()+"/ban", jsonBody(t, map[string]string{"reason": "test"})), "id", user.ID.String()),
		admin,
	)
	recorder := httptest.NewRecorder()
	handler.AdminBanUser(recorder, request)
	if recorder.Code != http.StatusAccepted || responseStatus(t, recorder) != "ban_cleanup_pending" {
		t.Fatalf("ban response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	pool := handlerTestPool(t)
	var banned, active bool
	var pending int
	if err := pool.QueryRow(context.Background(), `
		SELECT users.is_banned, peer.is_active,
		       COUNT(operation.id) FILTER (
		           WHERE operation.action = 'disconnect'
		             AND operation.state IN ('pending', 'core_applied', 'cleanup_pending')
		       )
		FROM users
		JOIN peers peer ON peer.user_id = users.id AND peer.id = $2
		LEFT JOIN peer_operations operation ON operation.previous_peer_id = peer.id
		WHERE users.id = $1
		GROUP BY users.is_banned, peer.is_active`, user.ID, activePeerID).Scan(&banned, &active, &pending); err != nil {
		t.Fatalf("load pending ban cleanup: %v", err)
	}
	if !banned || !active || pending != 1 {
		t.Fatalf("ban ordering diverged: banned=%t active=%t pending=%d", banned, active, pending)
	}
}

func TestDeleteUserReturnsStableActiveDeviceConflict(t *testing.T) {
	handler, user, _, _, _ := insertDeviceHandlerFixture(t)
	admin := &models.User{ID: uuid.New(), Groups: []string{"midorivpn-admins"}}

	deleteUserRequest := withUser(
		withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+user.ID.String(), nil), "id", user.ID.String()),
		admin,
	)
	deleteUserRecorder := httptest.NewRecorder()
	handler.AdminDeleteUser(deleteUserRecorder, deleteUserRequest)
	if deleteUserRecorder.Code != http.StatusConflict || responseErrorCode(t, deleteUserRecorder) != "active_devices_must_be_disconnected" {
		t.Fatalf("delete user response: status=%d body=%s", deleteUserRecorder.Code, deleteUserRecorder.Body.String())
	}
}

func TestDeleteServerStartsDrainingAndReturnsStableConflict(t *testing.T) {
	handler, _, _, _, _ := insertDeviceHandlerFixture(t)
	admin := &models.User{ID: uuid.New(), Groups: []string{"midorivpn-admins"}}
	listRecorder := httptest.NewRecorder()
	handler.AdminListServers(listRecorder, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/admin/servers", nil), admin))
	servers := decodeResponseData[struct {
		Items []models.VPNServer `json:"items"`
	}](t, listRecorder)
	if len(servers.Items) != 1 {
		t.Fatalf("server fixture count = %d", len(servers.Items))
	}
	serverID := servers.Items[0].ID
	request := withUser(
		withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/admin/servers/"+serverID.String(), nil), "id", serverID.String()),
		admin,
	)
	recorder := httptest.NewRecorder()
	handler.AdminDeleteServer(recorder, request)
	if recorder.Code != http.StatusConflict || responseErrorCode(t, recorder) != "server_not_drained" {
		t.Fatalf("delete server response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
