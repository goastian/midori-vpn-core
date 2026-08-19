package api

import (
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/goastian/midori-vpn-core/internal/wg"
)

var (
	httpRequestsTotal atomic.Uint64
	http4xxTotal      atomic.Uint64
	http5xxTotal      atomic.Uint64
)

// RecordRequest increments the global Prometheus request counters using modern atomic types
func RecordRequest(statusCode int) {
	httpRequestsTotal.Add(1)
	if statusCode >= 400 && statusCode < 500 {
		http4xxTotal.Add(1)
	} else if statusCode >= 500 {
		http5xxTotal.Add(1)
	}
}

type MetricsExporter struct {
	mgr *wg.Manager
}

func NewMetricsExporter(mgr *wg.Manager) *MetricsExporter {
	return &MetricsExporter{mgr: mgr}
}

// Handler outputs Prometheus-compatible plain text metrics
func (m *MetricsExporter) Handler(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	activePeers := 0
	if m.mgr != nil {
		if stats, err := m.mgr.ServerStats(); err == nil {
			activePeers = stats.PeerCount
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "# HELP midori_vpn_active_peers Current number of active WireGuard peers.\n")
	fmt.Fprintf(w, "# TYPE midori_vpn_active_peers gauge\n")
	fmt.Fprintf(w, "midori_vpn_active_peers %d\n\n", activePeers)

	fmt.Fprintf(w, "# HELP midori_vpn_http_requests_total Total number of HTTP API requests received.\n")
	fmt.Fprintf(w, "# TYPE midori_vpn_http_requests_total counter\n")
	fmt.Fprintf(w, "midori_vpn_http_requests_total %d\n\n", httpRequestsTotal.Load())

	fmt.Fprintf(w, "# HELP midori_vpn_http_4xx_total Total number of HTTP 4xx client errors.\n")
	fmt.Fprintf(w, "# TYPE midori_vpn_http_4xx_total counter\n")
	fmt.Fprintf(w, "midori_vpn_http_4xx_total %d\n\n", http4xxTotal.Load())

	fmt.Fprintf(w, "# HELP midori_vpn_http_5xx_total Total number of HTTP 5xx server errors.\n")
	fmt.Fprintf(w, "# TYPE midori_vpn_http_5xx_total counter\n")
	fmt.Fprintf(w, "midori_vpn_http_5xx_total %d\n\n", http5xxTotal.Load())

	fmt.Fprintf(w, "# HELP midori_vpn_memory_alloc_bytes Current allocated memory in bytes.\n")
	fmt.Fprintf(w, "# TYPE midori_vpn_memory_alloc_bytes gauge\n")
	fmt.Fprintf(w, "midori_vpn_memory_alloc_bytes %d\n\n", mem.Alloc)

	fmt.Fprintf(w, "# HELP midori_vpn_goroutines Number of running goroutines.\n")
	fmt.Fprintf(w, "# TYPE midori_vpn_goroutines gauge\n")
	fmt.Fprintf(w, "midori_vpn_goroutines %d\n\n", runtime.NumGoroutine())

	fmt.Fprintf(w, "# HELP midori_vpn_uptime_seconds Uptime in seconds.\n")
	fmt.Fprintf(w, "# TYPE midori_vpn_uptime_seconds gauge\n")
	fmt.Fprintf(w, "midori_vpn_uptime_seconds %d\n", int64(time.Since(startTime).Seconds()))
}
