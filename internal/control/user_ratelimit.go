package control

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// userRateLimiter tracks per-user rate limiters with automatic cleanup of
// stale entries. It mirrors the IP-based limiter in internal/api/ratelimit.go
// but is keyed by user ID string instead of IP address.
type userRateLimiter struct {
	mu       sync.Mutex
	entries  map[string]*userEntry
	rps      rate.Limit
	burst    int
}

type userEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newUserRateLimiter(rps float64, burst int) *userRateLimiter {
	ul := &userRateLimiter{
		entries: make(map[string]*userEntry),
		rps:     rate.Limit(rps),
		burst:   burst,
	}
	go ul.cleanup()
	return ul
}

// Allow returns true when the user has not exceeded the configured rate limit.
func (ul *userRateLimiter) Allow(userID string) bool {
	ul.mu.Lock()
	defer ul.mu.Unlock()

	e, exists := ul.entries[userID]
	if !exists {
		l := rate.NewLimiter(ul.rps, ul.burst)
		ul.entries[userID] = &userEntry{limiter: l, lastSeen: time.Now()}
		return l.Allow()
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// cleanup removes entries not seen in the last 10 minutes.
func (ul *userRateLimiter) cleanup() {
	for {
		time.Sleep(5 * time.Minute)
		ul.mu.Lock()
		for id, e := range ul.entries {
			if time.Since(e.lastSeen) > 10*time.Minute {
				delete(ul.entries, id)
			}
		}
		ul.mu.Unlock()
	}
}
