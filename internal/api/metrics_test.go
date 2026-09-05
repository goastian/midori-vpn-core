package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"
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
		"midori_vpn_database_pool_max_connections 0",
		"midori_vpn_database_waiting_locks 0",
		"midori_vpn_database_statement_stats_available 0",
		"midori_vpn_reconciliation_divergent_peers",
		"midori_vpn_reconciliation_cleanup_pending",
		"midori_vpn_peer_operations_pending",
		"midori_vpn_desired_state_renewals_total",
		"midori_vpn_desired_state_renewal_errors_total",
		"midori_vpn_node_auth_failures_total",
	} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("metrics output missing %q", expected)
		}
	}
	if metricValue(t, response.Body.String(), "midori_vpn_connection_provision_failures_total") < 1 {
		t.Fatal("provision failure counter was not incremented")
	}
}

func TestObservabilityHandlerAllowsOnlyPrivateGETRoutes(t *testing.T) {
	handler := NewObservabilityHandler(nil, nil)

	metricsResponse := httptest.NewRecorder()
	handler.ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsResponse.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", metricsResponse.Code)
	}

	postResponse := httptest.NewRecorder()
	handler.ServeHTTP(postResponse, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if postResponse.Code != http.StatusMethodNotAllowed || postResponse.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST status/Allow = %d/%q", postResponse.Code, postResponse.Header().Get("Allow"))
	}

	discoveryResponse := httptest.NewRecorder()
	handler.ServeHTTP(discoveryResponse, httptest.NewRequest(http.MethodGet, "/api/v1/observability/targets", nil))
	if discoveryResponse.Code != http.StatusNotFound {
		t.Fatalf("regional discovery status = %d, want 404", discoveryResponse.Code)
	}
}

func TestPrometheusLabelEscapesSpecialCharacters(t *testing.T) {
	if got, want := prometheusLabel("wire\\guard\n\"node\""), `wire\\guard\n\"node\"`; got != want {
		t.Fatalf("prometheusLabel() = %q, want %q", got, want)
	}
}

func TestRegionalDiscoveryAndFleetMetricsUseOperationalNodes(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	t.Cleanup(pool.Close)
	multiclusterRepo := repo.NewMulticlusterRepo(pool)
	cluster := &models.Cluster{
		Name: "metrics-" + uuid.NewString(), Region: "test", State: models.ClusterStateActive,
	}
	if err := multiclusterRepo.CreateCluster(context.Background(), cluster); err != nil {
		t.Fatalf("create cluster: %v", err)
	}
	activeNode := &models.CoreNode{
		ClusterID: cluster.ID, Name: "active-" + uuid.NewString()[:8],
		ManagementHost: "active.metrics.test.invalid", State: models.ClusterStateActive,
	}
	inactiveNode := &models.CoreNode{
		ClusterID: cluster.ID, Name: "inactive-" + uuid.NewString()[:8],
		ManagementHost: "inactive.metrics.test.invalid", State: models.ClusterStateInactive,
	}
	for _, node := range []*models.CoreNode{activeNode, inactiveNode} {
		if err := multiclusterRepo.CreateNode(context.Background(), node); err != nil {
			t.Fatalf("create node: %v", err)
		}
		identity := make([]byte, 32)
		if _, err := rand.Read(identity); err != nil {
			t.Fatalf("generate identity: %v", err)
		}
		if _, err := pool.Exec(context.Background(), `
			UPDATE core_nodes SET identity_public_key = $2, enrolled_at = NOW()
			WHERE id = $1`, node.ID, identity); err != nil {
			t.Fatalf("enroll node fixture: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM core_nodes WHERE id IN ($1, $2)`, activeNode.ID, inactiveNode.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})

	exporter := NewMetricsExporter(nil, pool)
	discoveryResponse := httptest.NewRecorder()
	exporter.DiscoveryHandler(discoveryResponse, httptest.NewRequest(http.MethodGet, "/api/v1/observability/targets", nil))
	if discoveryResponse.Code != http.StatusOK {
		t.Fatalf("discovery status = %d: %s", discoveryResponse.Code, discoveryResponse.Body.String())
	}
	var groups []prometheusTargetGroup
	if err := json.NewDecoder(discoveryResponse.Body).Decode(&groups); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	activeFound := false
	for _, group := range groups {
		if len(group.Targets) == 1 && group.Targets[0] == "active.metrics.test.invalid:9443" {
			activeFound = group.Labels["cluster"] == cluster.Name && group.Labels["node"] == activeNode.Name && group.Labels["role"] == "regional"
		}
		if len(group.Targets) == 1 && group.Targets[0] == "inactive.metrics.test.invalid:9443" {
			t.Fatal("inactive node appeared in regional discovery")
		}
	}
	if !activeFound {
		t.Fatal("active enrolled regional node missing from discovery")
	}

	metricsResponse := httptest.NewRecorder()
	exporter.Handler(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := metricsResponse.Body.String()
	labels := `cluster="` + cluster.Name + `",node="` + activeNode.Name + `"`
	for _, expected := range []string{
		"midori_vpn_node_last_seen_timestamp_seconds{" + labels + "} 0",
		"midori_vpn_node_revision_drift{" + labels + "} 1",
		"midori_vpn_node_version_compatible{" + labels + "} 0",
		"midori_vpn_node_health_status{" + labels + `,status="unknown"} 1`,
		"midori_vpn_node_desired_expires_timestamp_seconds{" + labels + "} 0",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("fleet metrics missing %q", expected)
		}
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
