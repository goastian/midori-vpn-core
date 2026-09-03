package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/httpx"
)

func TestJWKSProviderCoalescesConcurrentRefreshRequests(t *testing.T) {
	var calls atomic.Int64
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		if call == 2 {
			close(refreshStarted)
			<-releaseRefresh
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	provider, err := NewJWKSProvider(&config.Config{
		AuthentikJWKSURL: server.URL,
		ConfigDir:        t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewJWKSProvider: %v", err)
	}
	t.Cleanup(provider.Close)

	provider.mu.Lock()
	provider.fetchedAt = time.Time{}
	provider.mu.Unlock()

	var readers sync.WaitGroup
	readers.Add(64)
	for range 64 {
		go func() {
			defer readers.Done()
			_ = provider.KeySet()
		}()
	}
	readers.Wait()
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		close(releaseRefresh)
		t.Fatal("JWKS refresh did not start")
	}

	for range 64 {
		_ = provider.KeySet()
	}
	close(releaseRefresh)

	deadline := time.Now().Add(time.Second)
	for provider.isStale() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 2 {
		t.Fatalf("JWKS requests = %d, want one preload and one refresh", calls.Load())
	}
}

func TestJWKSRefreshRejectsOversizedResponseWithoutLeakingBody(t *testing.T) {
	secret := "jwks-provider-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(secret + strings.Repeat("x", httpx.MaxResponseBytes)))
	}))
	defer server.Close()

	provider := &JWKSProvider{
		cfg:        &config.Config{AuthentikJWKSURL: server.URL},
		cacheDir:   t.TempDir(),
		httpClient: server.Client(),
	}
	err := provider.refresh(context.Background())
	var remoteErr *httpx.RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Code != "response_too_large" {
		t.Fatalf("refresh() error = %#v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("provider body leaked through error: %q", err.Error())
	}
}

func TestJWKSProviderCloseCancelsInFlightRefresh(t *testing.T) {
	var calls atomic.Int64
	refreshStarted := make(chan struct{})
	requestCanceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 2 {
			close(refreshStarted)
			<-r.Context().Done()
			close(requestCanceled)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	provider, err := NewJWKSProviderWithContext(ctx, &config.Config{
		AuthentikJWKSURL: server.URL,
		ConfigDir:        t.TempDir(),
	})
	if err != nil {
		cancel()
		t.Fatalf("NewJWKSProviderWithContext: %v", err)
	}
	provider.mu.Lock()
	provider.fetchedAt = time.Time{}
	provider.mu.Unlock()
	_ = provider.KeySet()

	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		provider.Close()
		cancel()
		t.Fatal("JWKS refresh did not start")
	}
	cancel()

	closed := make(chan struct{})
	go func() {
		provider.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("JWKS provider did not stop after cancellation")
	}
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("in-flight JWKS request did not observe cancellation")
	}
}
