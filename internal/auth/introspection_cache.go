package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
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
	// leeway before exp at which we consider the cached entry stale
	expLeeway = 30 * time.Second
)

type introspectionCacheEntry struct {
	claims    *IntrospectionClaims
	err       error
	expiresAt time.Time
}

type introspectionCache struct {
	mu      sync.RWMutex
	entries map[string]introspectionCacheEntry
}

var globalIntrospectionCache = &introspectionCache{
	entries: make(map[string]introspectionCacheEntry),
}

func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (c *introspectionCache) get(key string) (introspectionCacheEntry, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return introspectionCacheEntry{}, false
	}
	if time.Now().After(entry.expiresAt) {
		return introspectionCacheEntry{}, false
	}
	return entry, true
}

func (c *introspectionCache) set(key string, entry introspectionCacheEntry) {
	c.mu.Lock()
	c.entries[key] = entry
	// Opportunistic cleanup to avoid unbounded growth.
	if len(c.entries) > 2048 {
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, k)
			}
		}
	}
	c.mu.Unlock()
}

// InvalidateIntrospection removes a token from the cache. Useful when a caller
// observes the token has been revoked (e.g., explicit logout).
func InvalidateIntrospection(token string) {
	if token == "" {
		return
	}
	key := tokenCacheKey(token)
	globalIntrospectionCache.mu.Lock()
	delete(globalIntrospectionCache.entries, key)
	globalIntrospectionCache.mu.Unlock()
}

// IntrospectTokenCached wraps IntrospectToken with an in-memory cache keyed by
// the SHA-256 of the token. The positive TTL is bounded by the token's own
// exp claim (minus a small leeway) so expired tokens never come back as valid.
func IntrospectTokenCached(cfg *config.Config, token string) (*IntrospectionClaims, error) {
	if token == "" {
		return IntrospectToken(cfg, token)
	}

	key := tokenCacheKey(token)

	if entry, ok := globalIntrospectionCache.get(key); ok {
		if entry.err != nil {
			return nil, entry.err
		}
		return entry.claims, nil
	}

	claims, err := IntrospectToken(cfg, token)
	if err != nil {
		globalIntrospectionCache.set(key, introspectionCacheEntry{
			err:       err,
			expiresAt: time.Now().Add(negativeTTL),
		})
		return nil, err
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

	globalIntrospectionCache.set(key, introspectionCacheEntry{
		claims:    claims,
		expiresAt: time.Now().Add(ttl),
	})
	return claims, nil
}
