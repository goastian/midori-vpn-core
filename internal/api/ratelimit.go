package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
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
local member = ARGV[4]
local clearBefore = now - windowMs

redis.call('ZREMRANGEBYSCORE', key, '-inf', clearBefore)
local current = redis.call('ZCARD', key)
if current < limit then
    redis.call('ZADD', key, now, member)
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
	now      func() time.Time
	nextGC   time.Time
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
		now:      time.Now,
	}
	ipl.nextGC = ipl.now().Add(time.Minute)
	return ipl
}

func (ipl *ipLimiter) getLimiter(ip string) *rate.Limiter {
	ipl.mu.Lock()
	defer ipl.mu.Unlock()

	now := ipl.now()
	if !now.Before(ipl.nextGC) {
		ipl.cleanupLocked(now)
		ipl.nextGC = now.Add(time.Minute)
	}

	v, exists := ipl.limiters[ip]
	if !exists {
		limiter := rate.NewLimiter(ipl.rps, ipl.burst)
		ipl.limiters[ip] = &visitorEntry{limiter: limiter, lastSeen: now}
		return limiter
	}

	v.lastSeen = now
	return v.limiter
}

func (ipl *ipLimiter) cleanupLocked(now time.Time) {
	for ip, visitor := range ipl.limiters {
		if now.Sub(visitor.lastSeen) > 3*time.Minute {
			delete(ipl.limiters, ip)
		}
	}
}

// DistributedRateLimiter combines Redis sliding window with memory fallback
type DistributedRateLimiter struct {
	rdb         *redis.Client
	local       *ipLimiter
	limit       int
	windowMs    int64
	trustedNets clientip.TrustedProxies
	redisNeeded bool
	redisErr    error
	now         func() time.Time
	nonce       func() string
}

func NewDistributedRateLimiter(cfg *config.Config) *DistributedRateLimiter {
	var rdb *redis.Client
	var redisErr error
	if cfg.RedisURL != "" {
		opt, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			redisErr = fmt.Errorf("parse Redis rate limiter URL: %w", err)
		} else {
			rdb = redis.NewClient(opt)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := rdb.Ping(ctx).Err(); err != nil {
				redisErr = fmt.Errorf("ping Redis rate limiter: %w", err)
				slog.Warn("redis rate limiter ping failed", "fallback_allowed", cfg.AuthentikClientID == "", "error", err)
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
		redisNeeded: cfg.AuthentikClientID != "",
		redisErr:    redisErr,
		now:         time.Now,
		nonce:       uuid.NewString,
	}
}

func (d *DistributedRateLimiter) Allow(ctx context.Context, ip string) (bool, error) {
	if d.rdb != nil {
		nowMs := d.now().UnixMilli()
		key := fmt.Sprintf("ratelimit:ip:%s", ip)
		res, err := slidingWindowScript.Run(ctx, d.rdb, []string{key}, nowMs, d.windowMs, d.limit, d.nonce()).Int()
		if err == nil {
			return res == 1, nil
		}
		if d.redisNeeded {
			return false, fmt.Errorf("distributed rate limiter unavailable: %w", err)
		}
		slog.Debug("redis rate limit check failed, falling back to local limiter", "error", err)
	} else if d.redisNeeded {
		if d.redisErr != nil {
			return false, d.redisErr
		}
		return false, errors.New("distributed rate limiter is not configured")
	}
	return d.local.getLimiter(ip).Allow(), nil
}

// RateLimitMiddleware applies distributed sliding-window rate limiting with Redis
func RateLimitMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	limiter := NewDistributedRateLimiter(cfg)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientip.RealIP(r, limiter.trustedNets)
			allowed, err := limiter.Allow(r.Context(), ip)
			if err != nil {
				slog.Error("distributed rate limiter unavailable", "error", err)
				respond.JsonError(w, "rate limiter unavailable", http.StatusServiceUnavailable)
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", "1")
				respond.JsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// EdgeHealthRateLimitMiddleware always protects the unauthenticated client
// probe, even in profiles where the general API limiter is disabled.
func EdgeHealthRateLimitMiddleware(trustedProxies string) func(http.Handler) http.Handler {
	limiter := newIPLimiter(5, 10)
	trustedNets := clientip.ParseTrustedProxies(trustedProxies)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientip.RealIP(r, trustedNets)
			if !limiter.getLimiter(ip).Allow() {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Retry-After", "1")
				respond.JsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
