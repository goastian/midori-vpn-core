package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/goastian/midori-vpn-core/internal/respond"
)

// refreshLimiter throttles `/api/v1/auth/refresh` per refresh_token (keyed by
// a SHA-256 hash so the raw token never appears in memory keys or logs).
//
// The IP-based rate limiter in ratelimit.go already protects against generic
// flooding, but it is bypassed by an attacker rotating IPs with a single
// stolen refresh_token. This limiter caps how often any individual token can
// be redeemed regardless of source IP.
//
// Bucket policy: burst=10, refill=1 token / 30s (≈ 10 attempts / 5 minutes).
// A legitimate client refreshes once per access-token lifetime (typically
// minutes), so the burst comfortably absorbs reconnects and tab restores.
type refreshLimiter struct {
	mu      sync.Mutex
	entries map[string]*refreshEntry
	rps     rate.Limit
	burst   int
}

type refreshEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newRefreshLimiter(rps float64, burst int) *refreshLimiter {
	rl := &refreshLimiter{
		entries: make(map[string]*refreshEntry),
		rps:     rate.Limit(rps),
		burst:   burst,
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if a refresh attempt for the given token should proceed.
// `key` must already be a hash; this function does not derive one.
func (rl *refreshLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, exists := rl.entries[key]
	if !exists {
		l := rate.NewLimiter(rl.rps, rl.burst)
		rl.entries[key] = &refreshEntry{limiter: l, lastSeen: time.Now()}
		return l.Allow()
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// cleanup expires entries unused for more than 30 minutes.
func (rl *refreshLimiter) cleanup() {
	for {
		time.Sleep(10 * time.Minute)
		rl.mu.Lock()
		for k, e := range rl.entries {
			if time.Since(e.lastSeen) > 30*time.Minute {
				delete(rl.entries, k)
			}
		}
		rl.mu.Unlock()
	}
}

// hashRefreshToken returns a hex-encoded SHA-256 of the refresh_token. We
// store the hash (not the token) as the limiter key so that map dumps,
// debuggers, or accidental logs cannot leak credentials.
func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// RefreshRateLimitMiddleware applies per-refresh_token throttling to the
// next handler. It expects a JSON body of the form `{ "refresh_token": "…" }`
// (matching control.RefreshRequest). If the body cannot be parsed it falls
// through to the underlying handler unchanged so that the canonical 400
// response is returned by the OAuth handler.
//
// This middleware MUST run after the body-size limit (1 MiB) is applied —
// the global router already does so via http.MaxBytesReader.
func RefreshRateLimitMiddleware() func(http.Handler) http.Handler {
	// 10 attempts initially, refilled at 1 token / 30s ≈ 10 / 5 min steady.
	limiter := newRefreshLimiter(1.0/30.0, 10)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				// Body too large or transport error — let the next handler
				// produce its standard error response.
				r.Body = io.NopCloser(bytes.NewReader(nil))
				next.ServeHTTP(w, r)
				return
			}
			// Always restore the body so the downstream handler can re-read it.
			r.Body = io.NopCloser(bytes.NewReader(body))

			var req struct {
				RefreshToken string `json:"refresh_token"`
			}
			if jerr := json.Unmarshal(body, &req); jerr != nil || req.RefreshToken == "" {
				// Malformed or missing token — defer to handler's 400.
				next.ServeHTTP(w, r)
				return
			}

			if !limiter.Allow(hashRefreshToken(req.RefreshToken)) {
				w.Header().Set("Retry-After", "30")
				respond.JsonError(w, "too many refresh attempts; retry later", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
