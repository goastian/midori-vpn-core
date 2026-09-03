package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/httpx"
)

func TestIntrospectionRejectsOversizedResponseWithoutLeakingBody(t *testing.T) {
	secret := "provider-secret-that-must-not-be-logged"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(secret + strings.Repeat("x", httpx.MaxResponseBytes)))
	}))
	defer server.Close()

	_, status, responseBytes, err := doIntrospectionRequest(context.Background(), server.URL, url.Values{})
	var remoteErr *httpx.RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Code != "response_too_large" {
		t.Fatalf("error = %#v, want response_too_large", err)
	}
	if status != http.StatusOK || responseBytes != httpx.MaxResponseBytes+1 {
		t.Fatalf("metadata = status %d, bytes %d", status, responseBytes)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("provider body leaked through error: %q", err.Error())
	}
}

func TestIntrospectionProviderErrorDoesNotLeakBody(t *testing.T) {
	secret := "provider-error-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(secret))
	}))
	defer server.Close()

	_, _, responseBytes, err := doIntrospectionRequest(context.Background(), server.URL, url.Values{})
	var remoteErr *httpx.RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Code != "provider_rejected" || responseBytes != len(secret) {
		t.Fatalf("error = %#v, bytes = %d", err, responseBytes)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("provider body leaked through error: %q", err.Error())
	}
}
