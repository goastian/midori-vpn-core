package control_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/models"
)

func TestDashboardSummaryUsesDevicesAndHistoricalSessions(t *testing.T) {
	handler, user, deviceID, olderPeerID, activePeerID := insertDeviceHandlerFixture(t)
	pool := handlerTestPool(t)

	// The shared fixture owns a different pool handle to the same test database.
	// Update its rows and add a completed revoked device with no active access.
	if _, err := pool.Exec(context.Background(), `UPDATE devices SET alias = 'Work laptop' WHERE id = $1`, deviceID); err != nil {
		t.Fatalf("set dashboard device alias: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE peers SET bytes_sent = 10, bytes_received = 20 WHERE id = $1`, olderPeerID); err != nil {
		t.Fatalf("set historical dashboard traffic: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE peers SET bytes_sent = 30, bytes_received = 40 WHERE id = $1`, activePeerID); err != nil {
		t.Fatalf("set active dashboard traffic: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO devices (
			user_id, client_instance_id, reported_name, device_type,
			first_seen_at, last_seen_at, revoked_at
		) VALUES ($1, $2, 'Retired laptop', 'desktop', $3, $3, $3)`,
		user.ID, uuid.New(), time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("prepare dashboard fixture: %v", err)
	}

	request := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/control/dashboard/summary", nil), user)
	recorder := httptest.NewRecorder()
	handler.DashboardSummary(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dashboard summary: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	summary := decodeResponseData[models.DashboardSummary](t, recorder)
	if summary.RegisteredDevices != 1 || summary.ConnectedDevices != 1 {
		t.Fatalf("dashboard counted sessions as devices: %#v", summary)
	}
	if summary.MaxDevices < 1 || summary.AvailableDevices != summary.MaxDevices-summary.ConnectedDevices {
		t.Fatalf("unexpected dashboard quota: %#v", summary)
	}
	if summary.Traffic.BytesSent != 40 || summary.Traffic.BytesReceived != 60 {
		t.Fatalf("dashboard omitted historical traffic: %#v", summary.Traffic)
	}
	if len(summary.RecentSessions) != 2 || summary.RecentSessions[0].ID != activePeerID || summary.RecentSessions[1].ID != olderPeerID {
		t.Fatalf("unexpected recent sessions: %#v", summary.RecentSessions)
	}
	if summary.RecentSessions[0].DeviceID == nil || *summary.RecentSessions[0].DeviceID != deviceID || summary.RecentSessions[0].DeviceName != "Work laptop" {
		t.Fatalf("recent session did not use stable device identity: %#v", summary.RecentSessions[0])
	}
	if summary.Infrastructure != nil {
		t.Fatalf("non-admin summary exposed infrastructure: %#v", summary.Infrastructure)
	}
}

func TestDashboardSummaryIncludesInfrastructureForAdmin(t *testing.T) {
	handler, user, _, _, _ := insertDeviceHandlerFixture(t)
	user.Groups = []string{"vpn-admins"}

	request := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/control/dashboard/summary", nil), user)
	recorder := httptest.NewRecorder()
	handler.DashboardSummary(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("admin dashboard summary: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	summary := decodeResponseData[models.DashboardSummary](t, recorder)
	if summary.Infrastructure == nil {
		t.Fatal("admin dashboard omitted infrastructure")
	}
	if summary.Infrastructure.TotalUsers < 1 || summary.Infrastructure.TotalServers < 1 || summary.Infrastructure.TotalPeers < 2 {
		t.Fatalf("incomplete dashboard infrastructure: %#v", summary.Infrastructure)
	}
}

func TestDashboardSummaryRepresentsARealEmptyAccount(t *testing.T) {
	pool := handlerTestPool(t)
	user := insertUser(t, pool)
	handler := control.NewHandler(pool, &config.Config{})

	request := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/control/dashboard/summary", nil), user)
	recorder := httptest.NewRecorder()
	handler.DashboardSummary(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("empty dashboard summary: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	summary := decodeResponseData[models.DashboardSummary](t, recorder)
	if summary.RegisteredDevices != 0 || summary.ConnectedDevices != 0 {
		t.Fatalf("empty dashboard returned device activity: %#v", summary)
	}
	if summary.Traffic.BytesSent != 0 || summary.Traffic.BytesReceived != 0 || len(summary.RecentSessions) != 0 {
		t.Fatalf("empty dashboard returned session history: %#v", summary)
	}
	if summary.AvailableDevices != summary.MaxDevices {
		t.Fatalf("empty dashboard quota is inconsistent: %#v", summary)
	}
}

func TestDashboardSummaryRejectsMissingUser(t *testing.T) {
	pool := handlerTestPool(t)
	handler := control.NewHandler(pool, &config.Config{})
	recorder := httptest.NewRecorder()
	handler.DashboardSummary(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/control/dashboard/summary", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("dashboard without user: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
