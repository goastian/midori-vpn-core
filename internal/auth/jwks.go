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

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/goastian/midori-vpn-core/internal/config"
)

const jwksCacheFile = "jwks_cache.json"

type JWKSProvider struct {
	cfg             *config.Config
	mu              sync.RWMutex
	keySet          jwk.Set
	fetchedAt       time.Time
	cacheTTL        time.Duration
	cacheDir        string
	ctx             context.Context
	cancel          context.CancelFunc
	refreshRequests chan struct{}
	workers         sync.WaitGroup
	closeOnce       sync.Once
}

func NewJWKSProvider(cfg *config.Config) (*JWKSProvider, error) {
	return NewJWKSProviderWithContext(context.Background(), cfg)
}

func NewJWKSProviderWithContext(parent context.Context, cfg *config.Config) (*JWKSProvider, error) {
	cacheDir := cfg.ConfigDir
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}
	ctx, cancel := context.WithCancel(parent)

	p := &JWKSProvider{
		cfg:             cfg,
		cacheTTL:        1 * time.Hour,
		cacheDir:        cacheDir,
		ctx:             ctx,
		cancel:          cancel,
		refreshRequests: make(chan struct{}, 1),
	}

	// Preload with retry (3 attempts with exponential backoff)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := p.refresh(ctx); err != nil {
			lastErr = err
			slog.Warn("JWKS preload attempt failed", "attempt", attempt, "error", err)
			if attempt < 3 {
				if !waitForRetry(ctx, time.Duration(attempt)*2*time.Second) {
					lastErr = ctx.Err()
					break
				}
			}
			continue
		}
		lastErr = nil
		break
	}
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, fmt.Errorf("JWKS preload canceled: %w", err)
	}

	if lastErr != nil {
		slog.Warn("JWKS remote preload failed after 3 attempts, trying local fallback")
		if fbErr := p.loadFromDisk(); fbErr != nil {
			cancel()
			return nil, fmt.Errorf("JWKS preload from %s failed and no local fallback: %w", cfg.AuthentikJWKSURL, lastErr)
		}
		slog.Info("JWKS loaded from local fallback", "keys", p.keySet.Len())
	}

	p.workers.Add(1)
	go p.backgroundRefresh()

	return p, nil
}

func waitForRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (p *JWKSProvider) KeySet() jwk.Set {
	p.mu.RLock()
	keySet := p.keySet
	stale := time.Since(p.fetchedAt) > p.cacheTTL
	p.mu.RUnlock()

	if stale {
		p.requestRefresh()
	}

	return keySet
}

func (p *JWKSProvider) refresh(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
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

	set, err := jwk.Parse(body)
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

func (p *JWKSProvider) requestRefresh() {
	select {
	case <-p.ctx.Done():
	case p.refreshRequests <- struct{}{}:
	default:
	}
}

func (p *JWKSProvider) isStale() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return time.Since(p.fetchedAt) > p.cacheTTL
}

func (p *JWKSProvider) backgroundRefresh() {
	defer p.workers.Done()
	ticker := time.NewTicker(p.cacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if err := p.refresh(p.ctx); err != nil && p.ctx.Err() == nil {
				slog.Error("JWKS background refresh error", "error", err)
			}
		case <-p.refreshRequests:
			if p.isStale() {
				if err := p.refresh(p.ctx); err != nil && p.ctx.Err() == nil {
					slog.Error("JWKS requested refresh error", "error", err)
				}
			}
		}
	}
}

// Close stops background refresh and waits until any in-flight fetch exits.
func (p *JWKSProvider) Close() {
	p.closeOnce.Do(p.cancel)
	p.workers.Wait()
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

	set, err := jwk.Parse(data)
	if err != nil {
		return fmt.Errorf("parse cached JWKS: %w", err)
	}

	p.mu.Lock()
	p.keySet = set
	p.fetchedAt = time.Now()
	p.mu.Unlock()

	return nil
}
