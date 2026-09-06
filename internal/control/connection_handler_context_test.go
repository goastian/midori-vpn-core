package control

import (
	"context"
	"testing"
	"time"
)

func TestPostCoreCompletionContextOutlivesCanceledRequest(t *testing.T) {
	type contextKey string
	const key contextKey = "request-value"
	requestCtx, cancelRequest := context.WithCancel(context.WithValue(context.Background(), key, "kept"))
	cancelRequest()

	completionCtx, cancelCompletion := postCoreCompletionContext(requestCtx)
	defer cancelCompletion()
	if err := completionCtx.Err(); err != nil {
		t.Fatalf("completion context inherited request cancellation: %v", err)
	}
	if got := completionCtx.Value(key); got != "kept" {
		t.Fatalf("completion context value = %v, want kept", got)
	}
	deadline, ok := completionCtx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > postCoreCompletionTimeout {
		t.Fatalf("completion deadline = %v, bounded=%v", deadline, ok)
	}
}
