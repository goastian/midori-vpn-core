package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type healthEnvelope struct {
	OK   bool `json:"ok"`
	Data struct {
		Status string                 `json:"status"`
		Checks map[string]interface{} `json:"checks"`
	} `json:"data"`
}

func TestPublicReadyzOmitsDependencyDetails(t *testing.T) {
	checker := NewHealthChecker(nil, nil, nil)
	recorder := httptest.NewRecorder()
	checker.Readyz(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var response healthEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Data.Status != "ready" {
		t.Fatalf("response = %+v", response)
	}
	if response.Data.Checks != nil {
		t.Fatalf("public readiness leaked dependency checks: %+v", response.Data.Checks)
	}
}

func TestDetailedReadyzIncludesChecksContract(t *testing.T) {
	checker := NewHealthChecker(nil, nil, nil)
	recorder := httptest.NewRecorder()
	checker.DetailedReadyz(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/health", nil))

	var response healthEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Checks == nil {
		t.Fatal("protected readiness omitted checks contract")
	}
}
