package auth

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/goastian/midori-vpn-core/internal/config"
)

type JWKSProvider struct {
	cfg       *config.Config
	mu        sync.RWMutex
	keySet    jwk.Set
	fetchedAt time.Time
	cacheTTL  time.Duration
}

func NewJWKSProvider(cfg *config.Config) (*JWKSProvider, error) {
	p := &JWKSProvider{
		cfg:      cfg,
		cacheTTL: 1 * time.Hour,
	}

	if err := p.refresh(); err != nil {
		return nil, fmt.Errorf("initial JWKS fetch from %s: %w", cfg.AuthentikJWKSURL, err)
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

	log.Printf("JWKS refreshed: %d keys from %s", set.Len(), p.cfg.AuthentikJWKSURL)
	return nil
}

func (p *JWKSProvider) backgroundRefresh() {
	ticker := time.NewTicker(p.cacheTTL)
	defer ticker.Stop()

	for range ticker.C {
		if err := p.refresh(); err != nil {
			log.Printf("JWKS background refresh error: %v", err)
		}
	}
}
