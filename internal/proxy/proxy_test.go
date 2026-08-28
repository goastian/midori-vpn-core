package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/proxytoken"
)

type fixedResolver struct {
	ips []net.IP
	err error
}

func (r fixedResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return r.ips, r.err
}

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

func TestResolvePublicTargetsPinsValidatedDNSAnswers(t *testing.T) {
	server := New(&config.Config{}, nil)
	server.resolver = fixedResolver{ips: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2606:4700:4700::1111")}}
	targets, err := server.resolvePublicTargets(context.Background(), "example.test:443")
	if err != nil {
		t.Fatalf("resolvePublicTargets() error = %v", err)
	}
	want := map[string]bool{"1.1.1.1:443": true, "[2606:4700:4700::1111]:443": true}
	if len(targets) != len(want) {
		t.Fatalf("targets = %#v", targets)
	}
	for _, target := range targets {
		if !want[target] {
			t.Fatalf("unexpected validated target %q", target)
		}
	}
}

func TestResolvePublicTargetsFailsClosedForMixedDNSAnswers(t *testing.T) {
	server := New(&config.Config{}, nil)
	server.resolver = fixedResolver{ips: []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.200.1.2")}}
	if _, err := server.resolvePublicTargets(context.Background(), "rebinding.test:443"); !errors.Is(err, errForbiddenTarget) {
		t.Fatalf("mixed public/private DNS answers error = %v, want forbidden", err)
	}
}

func TestResolvePublicTargetsRejectsReservedAndLocalRanges(t *testing.T) {
	server := New(&config.Config{}, nil)
	for _, target := range []string{
		"127.0.0.1:443",
		"10.200.1.2:443",
		"100.64.0.1:443",
		"169.254.169.254:80",
		"192.0.2.1:443",
		"[::1]:443",
		"[2001:db8::1]:443",
	} {
		if _, err := server.resolvePublicTargets(context.Background(), target); !errors.Is(err, errForbiddenTarget) {
			t.Errorf("reserved target %q error = %v, want forbidden", target, err)
		}
	}
}

func TestResolvePublicTargetsRejectsMalformedAddresses(t *testing.T) {
	server := New(&config.Config{}, nil)
	for _, target := range []string{"example.test", "example.test:0", "example.test:65536"} {
		if _, err := server.resolvePublicTargets(context.Background(), target); !errors.Is(err, errInvalidTarget) {
			t.Errorf("malformed target %q error = %v, want invalid", target, err)
		}
	}
}

func TestServeHTTPReturnsForbiddenForPrivateTargets(t *testing.T) {
	const secret = "proxy-forbidden-target-secret"
	server := New(&config.Config{CredentialSigningSecret: secret, ProxyMaxConnsPerUser: 2}, nil)
	request := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:443", nil)
	request.Host = "127.0.0.1:443"
	request.Header.Set("Proxy-Authorization", "Bearer "+proxytoken.Generate(uuid.New(), secret, time.Minute))
	recorder := httptest.NewRecorder()

	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}
