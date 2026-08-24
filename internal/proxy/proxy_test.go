package proxy

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/proxytoken"
)

func TestAuthenticateAcceptsOnlyScopedProxyTokens(t *testing.T) {
	const secret = "proxy-token-test-secret"
	userID := uuid.New()
	server := New(&config.Config{CredentialSigningSecret: secret}, nil)

	t.Run("accepts valid proxy token", func(t *testing.T) {
		req := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
		req.Header.Set("Proxy-Authorization", "Bearer "+proxytoken.Generate(userID, secret, time.Minute))

		subject, err := server.authenticate(req)
		if err != nil {
			t.Fatalf("authenticate() error = %v", err)
		}
		if subject != userID.String() {
			t.Fatalf("authenticate() subject = %q, want %q", subject, userID)
		}
	})

	t.Run("rejects generic bearer token", func(t *testing.T) {
		req := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
		req.Header.Set("Proxy-Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature")

		if _, err := server.authenticate(req); err == nil {
			t.Fatal("authenticate() accepted a non proxy-scoped bearer token")
		}
	})
}
