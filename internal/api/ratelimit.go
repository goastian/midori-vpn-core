package api

import (
	"net"
	"net/http"
	"strings"
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
	trusted := parseTrustedProxies(cfg.TrustedProxies)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := realIP(r, trusted)
			if !limiter.getLimiter(ip).Allow() {
				w.Header().Set("Retry-After", "1")
				respond.JsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// parseTrustedProxies parses a comma-separated list of IPs and CIDRs into a
// list of *net.IPNet. A bare IP like "10.0.0.1" is treated as /32 (IPv4) or
// /128 (IPv6).
func parseTrustedProxies(raw string) []*net.IPNet {
	var nets []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			// Bare IP — convert to single-host CIDR
			ip := net.ParseIP(entry)
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err == nil {
			nets = append(nets, cidr)
		}
	}
	return nets
}

// isTrustedProxy returns true when remoteAddr is within one of the trusted
// networks. If no trusted proxies are configured, returns false (default deny).
func isTrustedProxy(remoteAddr string, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// realIP extracts the client IP. It only trusts X-Real-IP and X-Forwarded-For
// headers when the request comes from a trusted proxy.
func realIP(r *http.Request, trusted []*net.IPNet) string {
	if isTrustedProxy(r.RemoteAddr, trusted) {
		// Prefer X-Real-IP set by a trusted reverse proxy
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
		// Take the rightmost (last) IP from X-Forwarded-For — closest to our proxy
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	// Strip port from RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
