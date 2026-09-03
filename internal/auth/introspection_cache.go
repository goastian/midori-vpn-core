package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
	"golang.org/x/sync/singleflight"
)

// Introspection cache reduces pressure on the Authentik introspection endpoint,
// which is called on every proxy CONNECT and every authenticated API request.
// Without a cache, a single browsing session can saturate Authentik and cause
// transient 407 rejections from the proxy, which in turn makes Firefox display
// its native proxy-auth prompt even though the user token is still valid.
//
// The cache stores successful introspections until the token's own exp (capped
// at maxPositiveTTL) and negative results (failures) for a very short window
// so outages do not cause a thundering herd.

const (
	maxPositiveTTL = 5 * time.Minute
	negativeTTL    = 10 * time.Second
	cacheCapacity  = 2048
	// leeway before exp at which we consider the cached entry stale
	expLeeway = 30 * time.Second
)

type introspectionCacheEntry struct {
	claims    *IntrospectionClaims
	err       error
	expiresAt time.Time
}

type introspectionCache struct {
	mu         sync.Mutex
	entries    map[string]introspectionCacheEntry
	capacity   int
	generation uint64
	requests   singleflight.Group
}

var globalIntrospectionCache = newIntrospectionCache(cacheCapacity)

func newIntrospectionCache(capacity int) *introspectionCache {
	return &introspectionCache{
		entries:  make(map[string]introspectionCacheEntry),
		capacity: capacity,
	}
}

func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (c *introspectionCache) get(key string) (introspectionCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return introspectionCacheEntry{}, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return introspectionCacheEntry{}, false
	}
	return entry, true
}

func (c *introspectionCache) set(key string, entry introspectionCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(key, entry)
}

func (c *introspectionCache) setIfGeneration(key string, entry introspectionCacheEntry, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation {
		return
	}
	c.setLocked(key, entry)
}

func (c *introspectionCache) setLocked(key string, entry introspectionCacheEntry) {
	if c.capacity <= 0 {
		return
	}
	now := time.Now()
	for existingKey, existing := range c.entries {
		if now.After(existing.expiresAt) {
			delete(c.entries, existingKey)
		}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.capacity {
		c.evictEarliestLocked()
	}
	c.entries[key] = entry
}

func (c *introspectionCache) currentGeneration() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

func (c *introspectionCache) invalidate(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.generation++
	c.mu.Unlock()
	c.requests.Forget(key)
}

// evictEarliestLocked removes the entry that expires first. A lexical key
// tie-break makes the result independent from Go's randomized map iteration.
func (c *introspectionCache) evictEarliestLocked() {
	var victimKey string
	var victimExpiry time.Time
	for key, entry := range c.entries {
		if victimKey == "" || entry.expiresAt.Before(victimExpiry) ||
			(entry.expiresAt.Equal(victimExpiry) && key < victimKey) {
			victimKey = key
			victimExpiry = entry.expiresAt
		}
	}
	if victimKey != "" {
		delete(c.entries, victimKey)
	}
}

// InvalidateIntrospection removes a token from the cache. Useful when a caller
// observes the token has been revoked (e.g., explicit logout).
func InvalidateIntrospection(token string) {
	if token == "" {
		return
	}
	key := tokenCacheKey(token)
	globalIntrospectionCache.invalidate(key)
}

// IntrospectTokenCached wraps IntrospectToken with an in-memory cache keyed by
// the SHA-256 of the token. The positive TTL is bounded by the token's own
// exp claim (minus a small leeway) so expired tokens never come back as valid.
func IntrospectTokenCached(cfg *config.Config, token string) (*IntrospectionClaims, error) {
	if token == "" {
		return IntrospectToken(cfg, token)
	}

	key := tokenCacheKey(token)
	generation := globalIntrospectionCache.currentGeneration()

	if entry, ok := globalIntrospectionCache.get(key); ok {
		if entry.err != nil {
			return nil, entry.err
		}
		return entry.claims, nil
	}

	result, err, _ := globalIntrospectionCache.requests.Do(key, func() (interface{}, error) {
		// The first caller may have populated the cache before a waiter enters
		// the flight, so check again inside the serialized loader.
		if entry, ok := globalIntrospectionCache.get(key); ok {
			if entry.err != nil {
				return nil, entry.err
			}
			return entry.claims, nil
		}
		claims, loadErr := IntrospectToken(cfg, token)
		if loadErr != nil {
			globalIntrospectionCache.setIfGeneration(key, introspectionCacheEntry{
				err:       loadErr,
				expiresAt: time.Now().Add(negativeTTL),
			}, generation)
			return nil, loadErr
		}

		ttl := maxPositiveTTL
		if claims.Exp > 0 {
			remaining := time.Until(time.Unix(claims.Exp, 0)) - expLeeway
			if remaining < ttl {
				ttl = remaining
			}
		}
		if ttl <= 0 {
			// Token already at or past exp — do not cache as positive.
			slog.Debug("introspection claims already near/past exp, not caching")
			return claims, nil
		}

		globalIntrospectionCache.setIfGeneration(key, introspectionCacheEntry{
			claims:    claims,
			expiresAt: time.Now().Add(ttl),
		}, generation)
		return claims, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := result.(*IntrospectionClaims)
	if !ok {
		return nil, errors.New("invalid introspection cache result")
	}
	return claims, nil
}
