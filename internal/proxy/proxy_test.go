package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

func proxyTestCredentials(t *testing.T) (*proxytoken.Signer, *proxytoken.Verifier) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := proxytoken.NewSigner("control", "https://control.test", base64.RawURLEncoding.EncodeToString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := proxytoken.NewVerifier("https://control.test", "control="+base64.RawURLEncoding.EncodeToString(publicKey), false, "")
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

func (r fixedResolver) LookupIP(context.Context, string, string) ([]net.IP, error) {
	return r.ips, r.err
}

func TestAuthenticateAcceptsOnlyScopedProxyTokens(t *testing.T) {
	userID := uuid.New()
	serverID, clusterID := uuid.New(), uuid.New()
	signer, verifier := proxyTestCredentials(t)
	server := New(&config.Config{ProxyServerID: serverID.String(), TransportClusterID: clusterID.String()}, verifier)

	t.Run("accepts valid proxy token", func(t *testing.T) {
		req := httptest.NewRequest("CONNECT", "http://example.com:443", nil)
		token, err := signer.Issue(proxytoken.AudienceVPNProxy, userID, uuid.New(), serverID, clusterID, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+token)

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
	serverID, clusterID := uuid.New(), uuid.New()
	signer, verifier := proxyTestCredentials(t)
	server := New(&config.Config{ProxyServerID: serverID.String(), TransportClusterID: clusterID.String(), ProxyMaxConnsPerUser: 2}, verifier)
	request := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:443", nil)
	request.Host = "127.0.0.1:443"
	token, err := signer.Issue(proxytoken.AudienceVPNProxy, uuid.New(), uuid.New(), serverID, clusterID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Proxy-Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()

	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}
