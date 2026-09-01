package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMetricsExporterIncludesOperationalHistograms(t *testing.T) {
	RecordRequest(http.StatusServiceUnavailable, 150*time.Millisecond, http.MethodPost, "/api/v1/control/connections")

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	NewMetricsExporter(nil, nil).Handler(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	for _, expected := range []string{
		"midori_vpn_http_request_duration_seconds_bucket{le=\"0.25\"}",
		"midori_vpn_connection_provision_duration_seconds_count",
		"midori_vpn_connection_provision_failures_total",
		"midori_vpn_control_database_up 0",
	} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("metrics output missing %q", expected)
		}
	}
	if metricValue(t, response.Body.String(), "midori_vpn_connection_provision_failures_total") < 1 {
		t.Fatal("provision failure counter was not incremented")
	}
}

func TestPrometheusLabelEscapesSpecialCharacters(t *testing.T) {
	if got, want := prometheusLabel("wire\\guard\n\"node\""), `wire\\guard\n\"node\"`; got != want {
		t.Fatalf("prometheusLabel() = %q, want %q", got, want)
	}
}

func metricValue(t *testing.T, body, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+" ") {
			value, err := strconv.ParseFloat(strings.TrimPrefix(line, name+" "), 64)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			return value
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}
