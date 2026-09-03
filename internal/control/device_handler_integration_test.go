package control_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/models"
)

type deviceHandlerResponse struct {
	ID               uuid.UUID                `json:"id"`
	Alias            string                   `json:"alias"`
	DisplayName      string                   `json:"display_name"`
	Status           string                   `json:"status"`
	ActiveConnection *models.DeviceConnection `json:"active_connection"`
}

type deviceSessionsResponse struct {
	Items    []models.DeviceConnection `json:"items"`
	Page     int                       `json:"page"`
	PageSize int                       `json:"page_size"`
	Total    int                       `json:"total"`
}

func insertDeviceHandlerFixture(t *testing.T) (*control.Handler, *models.User, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	pool := handlerTestPool(t)
	user := insertUser(t, pool)

	var serverID uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO vpn_servers (name, host, endpoint, public_key, location, country_code, current_peers)
		VALUES ('Device handler', '', '', 'server-key', 'Test', 'TT', 1)
		RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, serverID) })

	clientInstanceID := uuid.New()
	var deviceID uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (user_id, client_instance_id, reported_name, device_type)
		VALUES ($1, $2, 'handler-host', 'desktop')
		RETURNING id`, user.ID, clientInstanceID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	olderPeerID := uuid.New()
	activePeerID := uuid.New()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO peers (
			id, user_id, server_id, public_key, assigned_ip, device_name,
			device_id, is_active, created_at
		) VALUES
			($1, $3, $4, $8, '10.77.0.2/32', 'handler-host', $5, FALSE, $6),
			($2, $3, $4, $9, '10.77.0.3/32', 'handler-host', $5, TRUE, $7)`,
		olderPeerID, activePeerID, user.ID, serverID, deviceID,
		time.Now().UTC().Add(-time.Hour), time.Now().UTC(), connectOperationKey(61), connectOperationKey(62)); err != nil {
		t.Fatalf("insert peers: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			UPDATE peer_operations SET state = 'failed', capacity_reserved = FALSE
			WHERE user_id = $1 AND state IN ('pending', 'core_applied', 'cleanup_pending')`, user.ID)
	})

	return control.NewHandler(pool, &config.Config{}), user, deviceID, olderPeerID, activePeerID
}

func TestDeviceHandlersSeparateActiveListAndPaginatedHistory(t *testing.T) {
	handler, user, deviceID, olderPeerID, activePeerID := insertDeviceHandlerFixture(t)

	listRequest := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/control/devices", nil), user)
	listRecorder := httptest.NewRecorder()
	handler.ListMyDevices(listRecorder, listRequest)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list devices: status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}
	devices := decodeResponseData[[]deviceHandlerResponse](t, listRecorder)
	if len(devices) != 1 || devices[0].ID != deviceID || devices[0].Status != "connected" {
		t.Fatalf("unexpected devices: %#v", devices)
	}
	if devices[0].ActiveConnection == nil || devices[0].ActiveConnection.ID != activePeerID {
		t.Fatalf("active session was not attached to its device: %#v", devices[0].ActiveConnection)
	}

	historyRequest := withUser(
		withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/control/devices/"+deviceID.String()+"/sessions?page=2&page_size=1", nil), "id", deviceID.String()),
		user,
	)
	historyRecorder := httptest.NewRecorder()
	handler.ListMyDeviceSessions(historyRecorder, historyRequest)
	if historyRecorder.Code != http.StatusOK {
		t.Fatalf("list history: status=%d body=%s", historyRecorder.Code, historyRecorder.Body.String())
	}
	history := decodeResponseData[deviceSessionsResponse](t, historyRecorder)
	if history.Page != 2 || history.PageSize != 1 || history.Total != 2 || len(history.Items) != 1 || history.Items[0].ID != olderPeerID {
		t.Fatalf("unexpected history page: %#v", history)
	}

	connectionsRequest := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/control/connections", nil), user)
	connectionsRecorder := httptest.NewRecorder()
	handler.ListMyConnections(connectionsRecorder, connectionsRequest)
	if connectionsRecorder.Code != http.StatusOK {
		t.Fatalf("list connections: status=%d body=%s", connectionsRecorder.Code, connectionsRecorder.Body.String())
	}
	connections := decodeResponseData[[]models.Peer](t, connectionsRecorder)
	if len(connections) != 1 || connections[0].ID != activePeerID {
		t.Fatalf("connections endpoint leaked history: %#v", connections)
	}
}

func TestUpdateDeviceAliasReturnsStableDevice(t *testing.T) {
	handler, user, deviceID, _, _ := insertDeviceHandlerFixture(t)
	request := withUser(
		withChiParam(httptest.NewRequest(http.MethodPatch, "/api/v1/control/devices/"+deviceID.String(), jsonBody(t, map[string]string{"alias": "Work laptop"})), "id", deviceID.String()),
		user,
	)
	recorder := httptest.NewRecorder()
	handler.UpdateMyDevice(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update alias: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	updated := decodeResponseData[deviceHandlerResponse](t, recorder)
	if updated.ID != deviceID || updated.Alias != "Work laptop" || updated.DisplayName != "Work laptop" {
		t.Fatalf("unexpected updated device: %#v", updated)
	}
}

func TestDeleteDeviceRevokesFirstAndReturnsDurableCleanupPending(t *testing.T) {
	handler, user, deviceID, _, activePeerID := insertDeviceHandlerFixture(t)
	request := withUser(
		withChiParam(httptest.NewRequest(http.MethodDelete, "/api/v1/control/devices/"+deviceID.String(), nil), "id", deviceID.String()),
		user,
	)
	recorder := httptest.NewRecorder()
	handler.DeleteMyDevice(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("delete device: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var pending struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&pending); err != nil ||
		pending.Data.Status != "device_cleanup_pending" || recorder.Header().Get("Retry-After") != "5" {
		t.Fatalf("unexpected cleanup response: status=%q retry=%q", pending.Data.Status, recorder.Header().Get("Retry-After"))
	}

	listRequest := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/control/devices", nil), user)
	listRecorder := httptest.NewRecorder()
	handler.ListMyDevices(listRecorder, listRequest)
	devices := decodeResponseData[[]deviceHandlerResponse](t, listRecorder)
	if len(devices) != 1 || devices[0].Status != "cleanup_pending" || devices[0].ActiveConnection == nil || devices[0].ActiveConnection.ID != activePeerID {
		t.Fatalf("pending cleanup hid access or failed to revoke the device: %#v", devices)
	}
}
