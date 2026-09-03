package api

import (
	"testing"
	"time"
)

func TestRefreshLimiterCleansStaleEntriesWithoutBackgroundWorker(t *testing.T) {
	clock := time.Unix(1_788_400_000, 0)
	limiter := newRefreshLimiter(1, 10)
	limiter.now = func() time.Time { return clock }
	limiter.nextGC = clock.Add(10 * time.Minute)
	limiter.Allow("old-token-hash")
	clock = clock.Add(31 * time.Minute)
	limiter.Allow("new-token-hash")

	if _, exists := limiter.entries["old-token-hash"]; exists {
		t.Fatal("stale refresh limiter was not removed")
	}
}
