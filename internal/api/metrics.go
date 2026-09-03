package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	controlpkg "github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/telemetry"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

var (
	httpRequestsTotal atomic.Uint64
	http4xxTotal      atomic.Uint64
	http5xxTotal      atomic.Uint64
	httpDuration      durationHistogram
	provisionDuration durationHistogram
	provisionFailures atomic.Uint64
)

const durationBucketCount = 11

const (
	ObservabilityPort    = 9443
	maxDiscoveredTargets = 2048
)

var durationBuckets = [durationBucketCount]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type durationHistogram struct {
	buckets [durationBucketCount]atomic.Uint64
	count   atomic.Uint64
	sumUS   atomic.Uint64
}

func (h *durationHistogram) observe(duration time.Duration) {
	seconds := duration.Seconds()
	for index, boundary := range durationBuckets {
		if seconds <= boundary {
			h.buckets[index].Add(1)
		}
	}
	h.count.Add(1)
	h.sumUS.Add(uint64(max(duration.Microseconds(), 0)))
}

// RecordRequest updates bounded, aggregate metrics. It deliberately avoids
// path, user, address and server labels so the exporter cannot become a source
// of credentials, browsing history or unbounded cardinality.
func RecordRequest(statusCode int, duration time.Duration, method, path string) {
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	httpRequestsTotal.Add(1)
	httpDuration.observe(duration)
	if statusCode >= 400 && statusCode < 500 {
		http4xxTotal.Add(1)
	} else if statusCode >= 500 {
		http5xxTotal.Add(1)
	}

	if method == http.MethodPost && path == "/api/v1/control/connections" {
		provisionDuration.observe(duration)
		if statusCode >= 400 {
			provisionFailures.Add(1)
		}
	}
}

type MetricsExporter struct {
	mgr  *wg.Manager
	pool *pgxpool.Pool
}

func NewMetricsExporter(mgr *wg.Manager, pool *pgxpool.Pool) *MetricsExporter {
	return &MetricsExporter{mgr: mgr, pool: pool}
}

func NewObservabilityHandler(mgr *wg.Manager, pool *pgxpool.Pool) http.Handler {
	exporter := NewMetricsExporter(mgr, pool)
	mux := http.NewServeMux()
	mux.Handle("/metrics", getOnly(http.HandlerFunc(exporter.Handler)))
	mux.Handle("/api/v1/observability/targets", getOnly(http.HandlerFunc(exporter.DiscoveryHandler)))
	return mux
}

func getOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type transportMetric struct {
	protocol string
	status   string
	count    int64
}

type controlMetrics struct {
	databaseUp  int
	transports  []transportMetric
	currentPeer int64
	maxPeers    int64
	nodes       []fleetNodeMetric
}

type fleetNodeMetric struct {
	cluster             string
	node                string
	lastSeenUnix        int64
	revisionDrift       int
	versionCompatible   int
	healthStatus        string
	currentPeers        int
	maxPeers            int
	desiredSignatureBad int
}

func (m *MetricsExporter) controlMetrics(parent context.Context) controlMetrics {
	if m.pool == nil {
		return controlMetrics{}
	}

	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()

	result := controlMetrics{databaseUp: 1}
	rows, err := m.pool.Query(ctx, `
		SELECT t.protocol, t.health_status, COUNT(*)
		FROM vpn_server_transports t
		JOIN vpn_servers s ON s.id = t.server_id
		WHERE s.is_active = TRUE AND t.enabled = TRUE
		GROUP BY t.protocol, t.health_status
		ORDER BY t.protocol, t.health_status`)
	if err != nil {
		result.databaseUp = 0
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var metric transportMetric
		if err := rows.Scan(&metric.protocol, &metric.status, &metric.count); err != nil {
			result.databaseUp = 0
			return result
		}
		result.transports = append(result.transports, metric)
	}
	if rows.Err() != nil {
		result.databaseUp = 0
		return result
	}
	rows.Close()

	if err := m.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(current_peers), 0), COALESCE(SUM(max_peers), 0)
		FROM vpn_servers
		WHERE is_active = TRUE`).Scan(&result.currentPeer, &result.maxPeers); err != nil {
		result.databaseUp = 0
		return result
	}

	rows, err = m.pool.Query(ctx, `
		SELECT cluster.name, node.name,
		       COALESCE(EXTRACT(EPOCH FROM node.last_seen_at)::BIGINT, 0),
		       CASE WHEN desired.revision IS NOT NULL
		                  AND observation.applied_revision = desired.revision THEN 0 ELSE 1 END,
		       CASE WHEN observation.version_compatible THEN 1 ELSE 0 END,
		       COALESCE(observation.health_status, 'unknown'),
		       COALESCE(observation.current_peers, 0),
		       COALESCE(observation.max_peers, 0),
		       CASE WHEN observation.last_error_code = 'desired_state_signature_invalid' THEN 1 ELSE 0 END
		FROM core_nodes node
		JOIN clusters cluster ON cluster.id = node.cluster_id
		LEFT JOIN LATERAL (
			SELECT revision FROM desired_revisions
			WHERE node_id = node.id ORDER BY revision DESC LIMIT 1
		) desired ON TRUE
		LEFT JOIN LATERAL (
			SELECT applied_revision, version_compatible, health_status,
			       current_peers, max_peers, last_error_code
			FROM node_observations
			WHERE node_id = node.id ORDER BY received_at DESC, id DESC LIMIT 1
		) observation ON TRUE
		WHERE cluster.state IN ('active', 'draining')
		  AND node.state IN ('active', 'draining')
		ORDER BY cluster.name, node.name`)
	if err != nil {
		result.databaseUp = 0
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var metric fleetNodeMetric
		if err := rows.Scan(
			&metric.cluster, &metric.node, &metric.lastSeenUnix,
			&metric.revisionDrift, &metric.versionCompatible,
			&metric.healthStatus, &metric.currentPeers, &metric.maxPeers,
			&metric.desiredSignatureBad,
		); err != nil {
			result.databaseUp = 0
			result.nodes = nil
			return result
		}
		result.nodes = append(result.nodes, metric)
	}
	if rows.Err() != nil {
		result.databaseUp = 0
		result.nodes = nil
	}
	return result
}

// Handler outputs Prometheus text format on the private Core listener.
func (m *MetricsExporter) Handler(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	activePeers := 0
	var bytesSent, bytesRecv int64
	if m.mgr != nil {
		if stats, err := m.mgr.ServerStats(); err == nil {
			activePeers = stats.PeerCount
			bytesSent = stats.TotalTX
			bytesRecv = stats.TotalRX
		}
	}
	control := m.controlMetrics(r.Context())
	reconciliation := controlpkg.ReconciliationMetricsSnapshot()

	var output strings.Builder
	writeMetric(&output, "midori_vpn_active_peers", "Current number of active WireGuard peers.", "gauge", activePeers)
	writeMetric(&output, "midori_vpn_bytes_sent_total", "Total bytes transmitted via WireGuard.", "counter", bytesSent)
	writeMetric(&output, "midori_vpn_bytes_received_total", "Total bytes received via WireGuard.", "counter", bytesRecv)
	writeMetric(&output, "midori_vpn_http_requests_total", "Total number of HTTP API requests received.", "counter", httpRequestsTotal.Load())
	writeMetric(&output, "midori_vpn_http_4xx_total", "Total number of HTTP 4xx client errors.", "counter", http4xxTotal.Load())
	writeMetric(&output, "midori_vpn_http_5xx_total", "Total number of HTTP 5xx server errors.", "counter", http5xxTotal.Load())
	writeHistogram(&output, "midori_vpn_http_request_duration_seconds", "HTTP API request duration in seconds.", &httpDuration)
	writeHistogram(&output, "midori_vpn_connection_provision_duration_seconds", "Control API peer provisioning duration in seconds.", &provisionDuration)
	writeMetric(&output, "midori_vpn_connection_provision_failures_total", "Failed Control API peer provisioning requests.", "counter", provisionFailures.Load())
	writeMetric(&output, "midori_vpn_memory_alloc_bytes", "Current allocated memory in bytes.", "gauge", mem.Alloc)
	writeMetric(&output, "midori_vpn_goroutines", "Number of running goroutines.", "gauge", runtime.NumGoroutine())
	writeMetric(&output, "midori_vpn_uptime_seconds", "Core uptime in seconds.", "gauge", int64(time.Since(startTime).Seconds()))
	writeMetric(&output, "midori_vpn_control_database_up", "Whether the Control database was available to the metrics exporter.", "gauge", control.databaseUp)
	writeMetric(&output, "midori_vpn_server_current_peers", "Current peers across active configured servers.", "gauge", control.currentPeer)
	writeMetric(&output, "midori_vpn_server_peer_capacity", "Maximum peer capacity across active configured servers.", "gauge", control.maxPeers)
	writeMetric(&output, "midori_vpn_reconciliation_divergent_peers", "Peers divergent in the latest reconciliation pass.", "gauge", reconciliation.DivergentPeers)
	writeMetric(&output, "midori_vpn_reconciliation_cleanup_pending", "Peer cleanups pending after the latest reconciliation pass.", "gauge", reconciliation.CleanupPending)
	writeMetric(&output, "midori_vpn_peer_operations_pending", "Durable peer operations that have not fully converged.", "gauge", reconciliation.PendingOperations)
	writeMetric(&output, "midori_vpn_reconciliation_observation_errors", "Core or database observation errors in the latest reconciliation pass.", "gauge", reconciliation.ObservationErrors)
	authFailures := telemetry.NodeAuthFailures()
	fmt.Fprintln(&output, "# HELP midori_vpn_node_auth_failures_total Rejected signed node requests by bounded failure class.")
	fmt.Fprintln(&output, "# TYPE midori_vpn_node_auth_failures_total counter")
	for _, metric := range []struct {
		reason string
		value  uint64
	}{
		{reason: "invalid_signature", value: authFailures[telemetry.NodeAuthInvalid]},
		{reason: "replay", value: authFailures[telemetry.NodeAuthReplay]},
		{reason: "unavailable", value: authFailures[telemetry.NodeAuthUnavailable]},
	} {
		fmt.Fprintf(&output, "midori_vpn_node_auth_failures_total{reason=\"%s\"} %d\n", metric.reason, metric.value)
	}
	fmt.Fprintln(&output)
	writeMetricHeader(&output, "midori_vpn_node_last_seen_timestamp_seconds", "Unix timestamp of the latest accepted heartbeat for an operational node.", "gauge")
	writeMetricHeader(&output, "midori_vpn_node_revision_drift", "Whether the latest observed revision differs from current desired state.", "gauge")
	writeMetricHeader(&output, "midori_vpn_node_version_compatible", "Whether the node reports compatibility with current desired state.", "gauge")
	writeMetricHeader(&output, "midori_vpn_node_health_status", "Latest bounded health status reported by an operational node.", "gauge")
	writeMetricHeader(&output, "midori_vpn_node_current_peers", "Current peers reported by an operational node.", "gauge")
	writeMetricHeader(&output, "midori_vpn_node_max_peers", "Maximum peers reported by an operational node.", "gauge")
	writeMetricHeader(&output, "midori_vpn_node_desired_signature_error", "Whether the node most recently rejected a desired-state signature.", "gauge")
	for _, node := range control.nodes {
		labels := fmt.Sprintf("cluster=\"%s\",node=\"%s\"", prometheusLabel(node.cluster), prometheusLabel(node.node))
		fmt.Fprintf(&output, "midori_vpn_node_last_seen_timestamp_seconds{%s} %d\n", labels, node.lastSeenUnix)
		fmt.Fprintf(&output, "midori_vpn_node_revision_drift{%s} %d\n", labels, node.revisionDrift)
		fmt.Fprintf(&output, "midori_vpn_node_version_compatible{%s} %d\n", labels, node.versionCompatible)
		fmt.Fprintf(&output, "midori_vpn_node_health_status{%s,status=\"%s\"} 1\n", labels, prometheusLabel(node.healthStatus))
		fmt.Fprintf(&output, "midori_vpn_node_current_peers{%s} %d\n", labels, node.currentPeers)
		fmt.Fprintf(&output, "midori_vpn_node_max_peers{%s} %d\n", labels, node.maxPeers)
		fmt.Fprintf(&output, "midori_vpn_node_desired_signature_error{%s} %d\n", labels, node.desiredSignatureBad)
	}
	for _, metric := range control.transports {
		fmt.Fprintf(&output, "midori_vpn_transport_status{protocol=\"%s\",status=\"%s\"} %d\n", prometheusLabel(metric.protocol), prometheusLabel(metric.status), metric.count)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(output.String()))
}

type prometheusTargetGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// DiscoveryHandler returns only non-principal nodes in an operational
// lifecycle state. Stale nodes deliberately remain targets so Prometheus can
// emit up=0 while the fleet heartbeat alert reports their stale observation.
func (m *MetricsExporter) DiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if m.pool == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	rows, err := m.pool.Query(ctx, `
		SELECT cluster.name, node.name, node.management_host
		FROM core_nodes node
		JOIN clusters cluster ON cluster.id = node.cluster_id
		WHERE cluster.is_principal = FALSE
		  AND cluster.state IN ('active', 'draining')
		  AND node.state IN ('active', 'draining')
		  AND octet_length(node.identity_public_key) = 32
		ORDER BY cluster.name, node.name
		LIMIT $1`, maxDiscoveredTargets+1)
	if err != nil {
		http.Error(w, "observability discovery unavailable", http.StatusServiceUnavailable)
		return
	}
	defer rows.Close()
	groups := make([]prometheusTargetGroup, 0)
	for rows.Next() {
		var cluster, node, host string
		if err := rows.Scan(&cluster, &node, &host); err != nil {
			http.Error(w, "observability discovery unavailable", http.StatusServiceUnavailable)
			return
		}
		if len(groups) == maxDiscoveredTargets {
			http.Error(w, "observability target limit exceeded", http.StatusServiceUnavailable)
			return
		}
		groups = append(groups, prometheusTargetGroup{
			Targets: []string{net.JoinHostPort(host, fmt.Sprint(ObservabilityPort))},
			Labels:  map[string]string{"cluster": cluster, "node": node, "role": "regional"},
		})
	}
	if rows.Err() != nil {
		http.Error(w, "observability discovery unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(groups)
}

func writeMetric(output *strings.Builder, name, help, metricType string, value any) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s %s\n%s %v\n\n", name, help, name, metricType, name, value)
}

func writeMetricHeader(output *strings.Builder, name, help, metricType string) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeHistogram(output *strings.Builder, name, help string, histogram *durationHistogram) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name)
	for index, boundary := range durationBuckets {
		fmt.Fprintf(output, "%s_bucket{le=\"%g\"} %d\n", name, boundary, histogram.buckets[index].Load())
	}
	count := histogram.count.Load()
	fmt.Fprintf(output, "%s_bucket{le=\"+Inf\"} %d\n", name, count)
	fmt.Fprintf(output, "%s_sum %g\n", name, float64(histogram.sumUS.Load())/1_000_000)
	fmt.Fprintf(output, "%s_count %d\n\n", name, count)
}

func prometheusLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
