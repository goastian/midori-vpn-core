package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/goastian/midori-vpn-core/internal/config"
)

func TestRedisSlidingWindowCountsConcurrentRequestsInSameMillisecond(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatalf("parse TEST_REDIS_URL: %v", err)
	}
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })

	const limit = 17
	fixed := time.UnixMilli(1_788_400_000_123)
	var sequence atomic.Uint64
	limiter := &DistributedRateLimiter{
		rdb:      client,
		local:    newIPLimiter(limit, limit),
		limit:    limit,
		windowMs: 1000,
		now:      func() time.Time { return fixed },
		nonce:    func() string { return fmt.Sprintf("nonce-%d", sequence.Add(1)) },
	}
	ip := "same-ms-" + uuid.NewString()
	key := "ratelimit:ip:" + ip
	t.Cleanup(func() { _ = client.Del(context.Background(), key).Err() })

	const attempts = 64
	var accepted atomic.Int64
	var failures atomic.Int64
	var workers sync.WaitGroup
	workers.Add(attempts)
	for range attempts {
		go func() {
			defer workers.Done()
			allowed, allowErr := limiter.Allow(context.Background(), ip)
			if allowErr != nil {
				failures.Add(1)
				return
			}
			if allowed {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()

	if failures.Load() != 0 {
		t.Fatalf("Redis limiter failures = %d", failures.Load())
	}
	if accepted.Load() != limit {
		t.Fatalf("accepted = %d, want %d", accepted.Load(), limit)
	}
	count, err := client.ZCard(context.Background(), key).Result()
	if err != nil {
		t.Fatalf("ZCARD: %v", err)
	}
	if count != limit {
		t.Fatalf("stored members = %d, want %d", count, limit)
	}
}

func TestDistributedRateLimiterFailsClosedWhenRedisIsRequired(t *testing.T) {
	sentinel := errors.New("redis unavailable")
	limiter := &DistributedRateLimiter{
		local:       newIPLimiter(100, 100),
		redisNeeded: true,
		redisErr:    sentinel,
	}
	allowed, err := limiter.Allow(context.Background(), "192.0.2.10")
	if allowed || !errors.Is(err, sentinel) {
		t.Fatalf("Allow() = %v, %v; want false and Redis error", allowed, err)
	}
}

func TestRateLimitMiddlewareReturnsUnavailableWhenRequiredRedisCannotInitialize(t *testing.T) {
	cfg := &config.Config{
		AuthentikClientID: "control-enabled",
		RedisURL:          "://invalid",
		RateLimitRPS:      10,
		RateLimitBurst:    10,
	}
	called := false
	handler := RateLimitMiddleware(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if called {
		t.Fatal("request reached handler without required Redis")
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}

func TestDistributedRateLimiterAllowsLocalFallbackWhenRedisIsOptional(t *testing.T) {
	limiter := &DistributedRateLimiter{
		local:    newIPLimiter(100, 100),
		redisErr: errors.New("optional Redis unavailable"),
	}
	allowed, err := limiter.Allow(context.Background(), "192.0.2.11")
	if err != nil || !allowed {
		t.Fatalf("Allow() = %v, %v; want local fallback", allowed, err)
	}
}

func TestIPLimiterCleansStaleEntriesWithoutBackgroundWorker(t *testing.T) {
	clock := time.Unix(1_788_400_000, 0)
	limiter := newIPLimiter(10, 10)
	limiter.now = func() time.Time { return clock }
	limiter.nextGC = clock.Add(time.Minute)
	limiter.getLimiter("192.0.2.1")
	clock = clock.Add(4 * time.Minute)
	limiter.getLimiter("192.0.2.2")

	if _, exists := limiter.limiters["192.0.2.1"]; exists {
		t.Fatal("stale IP limiter was not removed")
	}
}
