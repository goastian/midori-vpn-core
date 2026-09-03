// Package telemetry owns bounded process-local counters shared by network
// authentication and the private Prometheus exporter.
package telemetry

import "sync/atomic"

const (
	NodeAuthInvalid = iota
	NodeAuthReplay
	NodeAuthUnavailable
	nodeAuthReasonCount
)

var nodeAuthFailures [nodeAuthReasonCount]atomic.Uint64

func RecordNodeAuthFailure(reason int) {
	if reason >= 0 && reason < len(nodeAuthFailures) {
		nodeAuthFailures[reason].Add(1)
	}
}

func NodeAuthFailures() [nodeAuthReasonCount]uint64 {
	var snapshot [nodeAuthReasonCount]uint64
	for index := range nodeAuthFailures {
		snapshot[index] = nodeAuthFailures[index].Load()
	}
	return snapshot
}
