package control_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/models"
)

func TestQuotaUsesConfiguredLimitWithoutBilling(t *testing.T) {
	pool := handlerTestPool(t)
	user := insertUser(t, pool)
	for _, test := range []struct {
		name  string
		limit int
		want  int
	}{
		{"configured beta limit", 3, 3},
		{"default for zero", 0, 5},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := control.NewHandler(pool, &config.Config{MaxDevicesPerUser: test.limit})
			recorder := httptest.NewRecorder()
			handler.GetQuota(recorder, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/control/quota", nil), user))
			if recorder.Code != http.StatusOK {
				t.Fatalf("quota: status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			quota := decodeResponseData[models.UserQuota](t, recorder)
			if quota.MaxDevices != test.want || quota.AvailableDevices != test.want {
				t.Fatalf("quota = %#v, want maximum and available = %d", quota, test.want)
			}
		})
	}
}

func TestQuotaUsesPlanLimitWhenBillingIsConfigured(t *testing.T) {
	pool := handlerTestPool(t)
	user := insertUser(t, pool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entitlements": []map[string]any{{
				"is_active":    true,
				"plan":         map[string]any{"id": 1, "slug": "pro", "name": "Pro"},
				"entitlements": map[string]any{"midori-vpn.devices_max": 7},
			}},
		})
	}))
	defer server.Close()
	handler := control.NewHandler(pool, &config.Config{MaxDevicesPerUser: 3, AstianPaymentURL: server.URL})
	recorder := httptest.NewRecorder()
	handler.GetQuota(recorder, withUser(httptest.NewRequest(http.MethodGet, "/api/v1/control/quota", nil), user))
	if recorder.Code != http.StatusOK {
		t.Fatalf("quota: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	quota := decodeResponseData[models.UserQuota](t, recorder)
	if quota.MaxDevices != 7 || quota.PlanSlug != "pro" {
		t.Fatalf("quota = %#v, want pro with seven devices", quota)
	}
}
