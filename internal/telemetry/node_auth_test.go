package telemetry

import "testing"

func TestNodeAuthFailureCountersAreBounded(t *testing.T) {
	before := NodeAuthFailures()
	RecordNodeAuthFailure(NodeAuthReplay)
	RecordNodeAuthFailure(-1)
	RecordNodeAuthFailure(nodeAuthReasonCount)
	after := NodeAuthFailures()

	if after[NodeAuthReplay] != before[NodeAuthReplay]+1 {
		t.Fatalf("replay failures = %d, want %d", after[NodeAuthReplay], before[NodeAuthReplay]+1)
	}
	if after[NodeAuthInvalid] != before[NodeAuthInvalid] || after[NodeAuthUnavailable] != before[NodeAuthUnavailable] {
		t.Fatal("out-of-range reason changed a bounded authentication counter")
	}
}
