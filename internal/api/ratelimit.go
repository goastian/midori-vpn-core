package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"

	"github.com/goastian/midori-vpn-core/internal/clientip"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

// Lua script for atomic sliding-window rate limiting in Redis
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local clearBefore = now - windowMs

redis.call('ZREMRANGEBYSCORE', key, '-inf', clearBefore)
local current = redis.call('ZCARD', key)
if current < limit then
    redis.call('ZADD', key, now, now)
    redis.call('EXPIRE', key, math.ceil(windowMs / 1000) + 1)
    return 1
else
    return 0
end
`)

// ipLimiter tracks per-IP rate limiters in local memory (fallback).
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

// DistributedRateLimiter combines Redis sliding window with memory fallback
type DistributedRateLimiter struct {
	rdb         *redis.Client
	local       *ipLimiter
	limit       int
	windowMs    int64
	trustedNets clientip.TrustedProxies
}

func NewDistributedRateLimiter(cfg *config.Config) *DistributedRateLimiter {
	var rdb *redis.Client
	if cfg.RedisURL != "" {
		opt, err := redis.ParseURL(cfg.RedisURL)
		if err == nil {
			rdb = redis.NewClient(opt)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := rdb.Ping(ctx).Err(); err != nil {
				slog.Warn("redis rate limiter ping failed, using memory fallback", "error", err)
			} else {
				slog.Info("redis distributed rate limiter initialized")
			}
		}
	}

	limit := cfg.RateLimitBurst
	if limit <= 0 {
		limit = 60
	}

	return &DistributedRateLimiter{
		rdb:         rdb,
		local:       newIPLimiter(float64(cfg.RateLimitRPS), cfg.RateLimitBurst),
		limit:       limit,
		windowMs:    1000, // 1 second window
		trustedNets: clientip.ParseTrustedProxies(cfg.TrustedProxies),
	}
}

func (d *DistributedRateLimiter) Allow(ctx context.Context, ip string) bool {
	if d.rdb != nil {
		nowMs := time.Now().UnixMilli()
		key := fmt.Sprintf("ratelimit:ip:%s", ip)
		res, err := slidingWindowScript.Run(ctx, d.rdb, []string{key}, nowMs, d.windowMs, d.limit).Int()
		if err == nil {
			return res == 1
		}
		slog.Debug("redis rate limit check failed, falling back to local limiter", "error", err)
	}
	return d.local.getLimiter(ip).Allow()
}

// RateLimitMiddleware applies distributed sliding-window rate limiting with Redis
func RateLimitMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	limiter := NewDistributedRateLimiter(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientip.RealIP(r, limiter.trustedNets)
			if !limiter.Allow(r.Context(), ip) {
				w.Header().Set("Retry-After", "1")
				respond.JsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
