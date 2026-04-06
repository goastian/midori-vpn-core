package auth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/goastian/midori-vpn-core/internal/config"
)

const jwksCacheFile = "jwks_cache.json"

type JWKSProvider struct {
	cfg       *config.Config
	mu        sync.RWMutex
	keySet    jwk.Set
	fetchedAt time.Time
	cacheTTL  time.Duration
	cacheDir  string
}

func NewJWKSProvider(cfg *config.Config) (*JWKSProvider, error) {
	cacheDir := cfg.ConfigDir
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}

	p := &JWKSProvider{
		cfg:      cfg,
		cacheTTL: 1 * time.Hour,
		cacheDir: cacheDir,
	}

	// Preload with retry (3 attempts with exponential backoff)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := p.refresh(); err != nil {
			lastErr = err
			slog.Warn("JWKS preload attempt failed", "attempt", attempt, "error", err)
			if attempt < 3 {
				time.Sleep(time.Duration(attempt) * 2 * time.Second)
			}
			continue
		}
		lastErr = nil
		break
	}

	if lastErr != nil {
		slog.Warn("JWKS remote preload failed after 3 attempts, trying local fallback")
		if fbErr := p.loadFromDisk(); fbErr != nil {
			return nil, fmt.Errorf("JWKS preload from %s failed and no local fallback: %w", cfg.AuthentikJWKSURL, lastErr)
		}
		slog.Info("JWKS loaded from local fallback", "keys", p.keySet.Len())
	}

	go p.backgroundRefresh()

	return p, nil
}

func (p *JWKSProvider) KeySet() jwk.Set {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if time.Since(p.fetchedAt) > p.cacheTTL {
		go p.refresh()
	}

	return p.keySet
}

func (p *JWKSProvider) refresh() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.AuthentikJWKSURL, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("JWKS returned %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read JWKS body: %w", err)
	}

	set, err := jwk.ParseString(string(body))
	if err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	p.mu.Lock()
	p.keySet = set
	p.fetchedAt = time.Now()
	p.mu.Unlock()

	// Persist to disk for fallback
	p.saveToDisk(body)

	slog.Info("JWKS refreshed", "keys", set.Len(), "source", p.cfg.AuthentikJWKSURL)
	return nil
}

func (p *JWKSProvider) backgroundRefresh() {
	ticker := time.NewTicker(p.cacheTTL)
	defer ticker.Stop()

	for range ticker.C {
		if err := p.refresh(); err != nil {
			slog.Error("JWKS background refresh error", "error", err)
		}
	}
}

func (p *JWKSProvider) cachePath() string {
	return filepath.Join(p.cacheDir, jwksCacheFile)
}

func (p *JWKSProvider) saveToDisk(data []byte) {
	path := p.cachePath()
	if err := os.WriteFile(path, data, 0600); err != nil {
		slog.Warn("JWKS cache write failed", "path", path, "error", err)
	}
}

func (p *JWKSProvider) loadFromDisk() error {
	path := p.cachePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read JWKS cache %s: %w", path, err)
	}

	set, err := jwk.ParseString(string(data))
	if err != nil {
		return fmt.Errorf("parse cached JWKS: %w", err)
	}

	p.mu.Lock()
	p.keySet = set
	p.fetchedAt = time.Now()
	p.mu.Unlock()

	return nil
}
