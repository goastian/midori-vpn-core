package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
)

func TestJWTRequiresIntendedAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := testJWKS(t, key)
	for _, test := range []struct {
		name     string
		audience any
		clientID string
		want     bool
	}{
		{"matching", []string{"vpn-client"}, "vpn-client", true},
		{"multiple including intended", []string{"other-client", "vpn-client"}, "vpn-client", true},
		{"other application", []string{"other-client"}, "vpn-client", false},
		{"missing", nil, "vpn-client", false},
		{"empty", []string{}, "vpn-client", false},
		{"missing client configuration", []string{"vpn-client"}, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{AuthentikIssuer: "https://auth.test.local", AuthentikClientID: test.clientID}
			claims := map[string]any{
				"iss": cfg.AuthentikIssuer, "sub": "audience-user", "exp": time.Now().Add(time.Hour).Unix(),
				// An authorized party must not substitute for a missing/wrong audience.
				"azp": "vpn-client",
			}
			if test.audience != nil {
				claims["aud"] = test.audience
			}
			token := signToken(t, key, claims)
			if got := auth.ValidateTokenOnly(cfg, jwks, token); got != test.want {
				t.Errorf("ValidateTokenOnly = %v, want %v", got, test.want)
			}
			identity, err := auth.ValidateTokenAndExtractClaims(cfg, jwks, token)
			if (err == nil) != test.want {
				t.Errorf("ValidateTokenAndExtractClaims: identity=%#v error=%v, want accepted=%v", identity, err, test.want)
			}
		})
	}
}

func TestIntrospectionRequiresIntendedAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := testJWKS(t, key)
	for _, test := range []struct {
		name     string
		audience any
		want     bool
	}{
		{"string", "vpn-client", true},
		{"array", []string{"vpn-client"}, true},
		{"multiple", []string{"other-client", "vpn-client"}, true},
		{"other string", "other-client", false},
		{"other array", []string{"other-client"}, false},
		{"missing", nil, false},
		{"empty array", []string{}, false},
		{"malformed", 123, false},
		{"mixed array", []any{"vpn-client", 123}, false},
		{"null array member", []any{"vpn-client", nil}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"active": true, "sub": "introspection-user", "iss": "https://auth.test.local",
					"exp": time.Now().Add(time.Hour).Unix(), "aud": test.audience, "azp": "vpn-client",
				})
			}))
			defer server.Close()
			cfg := &config.Config{
				AuthentikIssuer: "https://auth.test.local", AuthentikClientID: "vpn-client",
				AuthentikClientSecret: "test-secret", AuthentikIntrospectionURLOverride: server.URL,
			}
			for _, kind := range []string{"opaque", "jwe"} {
				token := fmt.Sprintf("%s-%s-%d", kind, test.name, time.Now().UnixNano())
				if kind == "jwe" {
					token += ".a.b.c.d"
				}
				if got := auth.ValidateTokenOnly(cfg, jwks, token); got != test.want {
					t.Errorf("%s: accepted=%v, want %v", kind, got, test.want)
				}
				if _, err := auth.ValidateTokenAndExtractClaims(cfg, jwks, token); (err == nil) != test.want {
					t.Errorf("%s claims: error=%v, want accepted=%v", kind, err, test.want)
				}
				auth.InvalidateIntrospection(token)
			}
		})
	}
}

func TestCachedIntrospectionCannotAuthorizeAnotherClient(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "sub": "cached-user", "aud": "vpn-client", "exp": time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer server.Close()
	cfg := &config.Config{AuthentikClientID: "vpn-client", AuthentikClientSecret: "test-secret", AuthentikIntrospectionURLOverride: server.URL}
	token := fmt.Sprintf("cache-audience-%d", time.Now().UnixNano())
	defer auth.InvalidateIntrospection(token)
	if _, err := auth.IntrospectTokenCached(cfg, token); err != nil {
		t.Fatal(err)
	}
	other := *cfg
	other.AuthentikClientID = "another-client"
	if _, err := auth.IntrospectTokenCached(&other, token); err == nil {
		t.Fatal("cached introspection accepted the token for another client")
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected provider requests: %d", calls.Load())
	}
}

func TestIntrospectionDoesNotRetryRejectedTokens(t *testing.T) {
	for _, reason := range []string{"inactive", "expired", "malformed audience"} {
		t.Run(reason, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				claims := map[string]any{"active": true, "sub": "test-user", "aud": "vpn-client", "exp": time.Now().Add(time.Hour).Unix()}
				if r.URL.Path == "/override" {
					switch reason {
					case "inactive":
						claims["active"] = false
					case "expired":
						claims["exp"] = time.Now().Add(-time.Hour).Unix()
					case "malformed audience":
						claims["aud"] = 123
					}
				}
				_ = json.NewEncoder(w).Encode(claims)
			}))
			defer server.Close()
			cfg := &config.Config{
				AuthentikIssuer: server.URL, AuthentikClientID: "vpn-client", AuthentikClientSecret: "test-secret",
				AuthentikIntrospectionURLOverride: server.URL + "/override",
			}
			if _, err := auth.IntrospectToken(cfg, "rejected-token"); err == nil {
				t.Error("a rejection from the configured endpoint was bypassed by another endpoint")
			}
			if calls.Load() != 1 {
				t.Fatalf("provider requests = %d, want one authoritative rejection", calls.Load())
			}
		})
	}
}

func TestIntrospectionRetainsEndpointDiscoveryOnNotFound(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/override" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "test-user", "aud": "vpn-client"})
	}))
	defer server.Close()
	cfg := &config.Config{
		AuthentikIssuer: server.URL, AuthentikClientID: "vpn-client", AuthentikClientSecret: "test-secret",
		AuthentikIntrospectionURLOverride: server.URL + "/override",
	}
	if _, err := auth.IntrospectToken(cfg, "valid-token"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("provider requests = %d, want 404 then successful discovery", calls.Load())
	}
}
