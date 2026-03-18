package api

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

// ipLimiter tracks per-IP rate limiters with automatic cleanup of stale entries.
type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*visitorEntry
	rps      rate.Limit
	burst    int
}

type visitorEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPLimiter(rps float64, burst int) *ipLimiter {
	ipl := &ipLimiter{
		limiters: make(map[string]*visitorEntry),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
	go ipl.cleanup()
	return ipl
}

func (ipl *ipLimiter) getLimiter(ip string) *rate.Limiter {
	ipl.mu.Lock()
	defer ipl.mu.Unlock()

	v, exists := ipl.limiters[ip]
	if !exists {
		limiter := rate.NewLimiter(ipl.rps, ipl.burst)
		ipl.limiters[ip] = &visitorEntry{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// cleanup removes entries not seen in the last 3 minutes.
func (ipl *ipLimiter) cleanup() {
	for {
		time.Sleep(1 * time.Minute)
		ipl.mu.Lock()
		for ip, v := range ipl.limiters {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(ipl.limiters, ip)
			}
		}
		ipl.mu.Unlock()
	}
}

// RateLimitMiddleware applies per-IP token-bucket rate limiting.
// Requests that exceed the limit receive HTTP 429 Too Many Requests.
func RateLimitMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	limiter := newIPLimiter(float64(cfg.RateLimitRPS), cfg.RateLimitBurst)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := realIP(r)
			if !limiter.getLimiter(ip).Allow() {
				w.Header().Set("Retry-After", "1")
				respond.JsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// realIP extracts the client IP from X-Forwarded-For, X-Real-IP, or RemoteAddr.
func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
