package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
)

func TestIntrospectionCacheEvictsDeterministicallyAtCapacity(t *testing.T) {
	cache := newIntrospectionCache(2)
	expiry := time.Now().Add(time.Hour)
	cache.set("b", introspectionCacheEntry{expiresAt: expiry})
	cache.set("a", introspectionCacheEntry{expiresAt: expiry})
	cache.set("c", introspectionCacheEntry{expiresAt: expiry.Add(time.Minute)})

	if len(cache.entries) != 2 {
		t.Fatalf("cache size = %d, want 2", len(cache.entries))
	}
	if _, exists := cache.entries["a"]; exists {
		t.Fatal("lexically first equal-expiry entry was not evicted")
	}
	if _, exists := cache.entries["b"]; !exists {
		t.Fatal("unexpected eviction of key b")
	}
	if _, exists := cache.entries["c"]; !exists {
		t.Fatal("new cache entry is missing")
	}
}

func TestIntrospectionCacheNeverExceedsProductionCapacity(t *testing.T) {
	cache := newIntrospectionCache(cacheCapacity)
	baseExpiry := time.Now().Add(time.Hour)
	for index := 0; index < cacheCapacity+100; index++ {
		cache.set(fmt.Sprintf("token-%04d", index), introspectionCacheEntry{
			expiresAt: baseExpiry.Add(time.Duration(index) * time.Second),
		})
	}
	if len(cache.entries) != cacheCapacity {
		t.Fatalf("cache size = %d, want %d", len(cache.entries), cacheCapacity)
	}
}

func TestIntrospectionCacheSingleflightDeduplicatesConcurrentMisses(t *testing.T) {
	var calls atomic.Int64
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(requestStarted)
		}
		<-releaseRequest
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IntrospectionClaims{
			Active: true,
			Sub:    "singleflight-user",
			Aud:    tokenAudience{"client"},
			Exp:    time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer server.Close()

	token := fmt.Sprintf("singleflight-%d", time.Now().UnixNano())
	InvalidateIntrospection(token)
	t.Cleanup(func() { InvalidateIntrospection(token) })
	cfg := &config.Config{
		AuthentikClientID:                 "client",
		AuthentikClientSecret:             "secret",
		AuthentikIntrospectionURLOverride: server.URL,
	}

	const callers = 48
	results := make(chan error, callers)
	var workers sync.WaitGroup
	workers.Add(callers)
	for range callers {
		go func() {
			defer workers.Done()
			claims, err := IntrospectTokenCached(cfg, token)
			if err == nil && (claims == nil || claims.Sub != "singleflight-user") {
				err = fmt.Errorf("unexpected claims: %#v", claims)
			}
			results <- err
		}()
	}
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		close(releaseRequest)
		t.Fatal("introspection request did not start")
	}
	close(releaseRequest)
	workers.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Fatalf("IntrospectTokenCached: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("introspection requests = %d, want 1", calls.Load())
	}
}

func TestInvalidateIntrospectionDoesNotAllowInFlightRepopulation(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseRequest
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(IntrospectionClaims{
			Active: true,
			Sub:    "invalidated-user",
			Aud:    tokenAudience{"client"},
			Exp:    time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer server.Close()

	token := fmt.Sprintf("in-flight-invalidation-%d", time.Now().UnixNano())
	InvalidateIntrospection(token)
	t.Cleanup(func() { InvalidateIntrospection(token) })
	cfg := &config.Config{
		AuthentikClientID:                 "client",
		AuthentikClientSecret:             "secret",
		AuthentikIntrospectionURLOverride: server.URL,
	}

	result := make(chan error, 1)
	go func() {
		_, err := IntrospectTokenCached(cfg, token)
		result <- err
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		close(releaseRequest)
		t.Fatal("introspection request did not start")
	}
	InvalidateIntrospection(token)
	close(releaseRequest)
	if err := <-result; err != nil {
		t.Fatalf("IntrospectTokenCached: %v", err)
	}
	if _, exists := globalIntrospectionCache.get(tokenCacheKey(token)); exists {
		t.Fatal("in-flight introspection repopulated an invalidated cache entry")
	}
}
