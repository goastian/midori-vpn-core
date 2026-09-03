package api

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	controlpkg "github.com/goastian/midori-vpn-core/internal/control"
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
	for _, metric := range control.transports {
		fmt.Fprintf(&output, "midori_vpn_transport_status{protocol=\"%s\",status=\"%s\"} %d\n", prometheusLabel(metric.protocol), prometheusLabel(metric.status), metric.count)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(output.String()))
}

func writeMetric(output *strings.Builder, name, help, metricType string, value any) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s %s\n%s %v\n\n", name, help, name, metricType, name, value)
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
