package control

import (
	"testing"
	"time"
)

func TestUserRateLimiterCleansStaleEntriesWithoutBackgroundWorker(t *testing.T) {
	clock := time.Unix(1_788_400_000, 0)
	limiter := newUserRateLimiter(1, 10)
	limiter.now = func() time.Time { return clock }
	limiter.nextGC = clock.Add(5 * time.Minute)
	limiter.Allow("old-user")
	clock = clock.Add(11 * time.Minute)
	limiter.Allow("new-user")

	if _, exists := limiter.entries["old-user"]; exists {
		t.Fatal("stale user limiter was not removed")
	}
}
