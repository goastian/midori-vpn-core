package control_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

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
}

func TestBanBlocksFirstAndReportsPendingCleanup(t *testing.T) {
	handler, user, _, _, _ := insertDeviceHandlerFixture(t)
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
	servers := decodeResponseData[[]models.VPNServer](t, listRecorder)
	if len(servers) != 1 {
		t.Fatalf("server fixture count = %d", len(servers))
	}
	serverID := servers[0].ID
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
