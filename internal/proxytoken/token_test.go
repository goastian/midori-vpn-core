package proxytoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testCredentials(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner("control-2026-09", "https://control.test", base64.RawURLEncoding.EncodeToString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier("https://control.test", "control-2026-09="+base64.RawURLEncoding.EncodeToString(publicKey), false, "")
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

func TestMVPN2RoundTripBindsAllClaims(t *testing.T) {
	signer, verifier := testCredentials(t)
	userID, deviceID, serverID, clusterID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token, err := signer.Issue(AudienceVPNTunnel, userID, deviceID, serverID, clusterID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "mvpn2.") {
		t.Fatalf("token = %q", token)
	}
	claims, err := verifier.Verify(token, AudienceVPNTunnel, serverID, clusterID)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != userID || claims.DeviceID != deviceID || claims.ServerID != serverID || claims.ClusterID != clusterID || claims.TokenID == uuid.Nil || claims.KeyID != "control-2026-09" {
		t.Fatalf("claims were not preserved: %#v", claims)
	}
}

func TestMVPN2RejectsTamperingAndWrongScopeWithoutLegacyFallback(t *testing.T) {
	signer, verifier := testCredentials(t)
	serverID, clusterID := uuid.New(), uuid.New()
	token, err := signer.Issue(AudienceVPNProxy, uuid.New(), uuid.New(), serverID, clusterID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		token     string
		audience  string
		serverID  uuid.UUID
		clusterID uuid.UUID
		want      error
	}{
		{name: "tampered", token: token + "x", audience: AudienceVPNProxy, serverID: serverID, clusterID: clusterID, want: ErrInvalidSignature},
		{name: "audience", token: token, audience: AudienceVPNTunnel, serverID: serverID, clusterID: clusterID, want: ErrWrongAudience},
		{name: "server", token: token, audience: AudienceVPNProxy, serverID: uuid.New(), clusterID: clusterID, want: ErrWrongServer},
		{name: "cluster", token: token, audience: AudienceVPNProxy, serverID: serverID, clusterID: uuid.New(), want: ErrWrongCluster},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, got := verifier.Verify(test.token, test.audience, test.serverID, test.clusterID)
			if !errors.Is(got, test.want) {
				t.Fatalf("Verify error = %v, want %v", got, test.want)
			}
		})
	}
}

func TestMVPN2RejectsExpiredAndOversizedLifetime(t *testing.T) {
	signer, verifier := testCredentials(t)
	now := time.Unix(2_000_000_000, 0)
	signer.now = func() time.Time { return now }
	verifier.now = func() time.Time { return now.Add(2 * time.Minute) }
	serverID, clusterID := uuid.New(), uuid.New()
	token, err := signer.Issue(AudienceVPNProxy, uuid.New(), uuid.New(), serverID, clusterID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(token, AudienceVPNProxy, serverID, clusterID); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired Verify error = %v", err)
	}
	if _, err := signer.Issue(AudienceVPNProxy, uuid.New(), uuid.New(), serverID, clusterID, DefaultTTL+time.Second); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("oversized Issue error = %v", err)
	}
}

func TestMVPN2RejectsWrongIssuerUnknownKeyAndFutureIssueTime(t *testing.T) {
	signer, verifier := testCredentials(t)
	now := time.Unix(2_000_000_000, 0)
	signer.now = func() time.Time { return now }
	serverID, clusterID := uuid.New(), uuid.New()
	token, err := signer.Issue(AudienceVPNProxy, uuid.New(), uuid.New(), serverID, clusterID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	wrongIssuer, err := NewVerifier("https://other-control.test", "control-2026-09="+base64.RawURLEncoding.EncodeToString(signer.PublicKey()), false, "")
	if err != nil {
		t.Fatal(err)
	}
	wrongIssuer.now = func() time.Time { return now }
	if _, err := wrongIssuer.Verify(token, AudienceVPNProxy, serverID, clusterID); !errors.Is(err, ErrWrongIssuer) {
		t.Fatalf("wrong issuer error = %v", err)
	}

	unknownKey, err := NewVerifier("https://control.test", "replacement="+base64.RawURLEncoding.EncodeToString(signer.PublicKey()), false, "")
	if err != nil {
		t.Fatal(err)
	}
	unknownKey.now = func() time.Time { return now }
	if _, err := unknownKey.Verify(token, AudienceVPNProxy, serverID, clusterID); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("unknown key error = %v", err)
	}

	verifier.now = func() time.Time { return now.Add(-time.Minute) }
	if _, err := verifier.Verify(token, AudienceVPNProxy, serverID, clusterID); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("future issue time error = %v", err)
	}
}

func TestLegacyHMACRequiresExplicitOptIn(t *testing.T) {
	_, strict := testCredentials(t)
	serverID, clusterID, userID := uuid.New(), uuid.New(), uuid.New()
	legacy := GenerateLegacyProxy(userID, "development-only", time.Minute)
	if _, err := strict.Verify(legacy, AudienceVPNProxy, serverID, clusterID); !errors.Is(err, ErrLegacyNotPermitted) {
		t.Fatalf("strict legacy error = %v", err)
	}

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := NewVerifier("https://control.test", "control="+base64.RawURLEncoding.EncodeToString(publicKey), true, "development-only")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := dev.Verify(legacy, AudienceVPNProxy, serverID, clusterID)
	if err != nil || !claims.LegacyHMAC || claims.UserID != userID {
		t.Fatalf("legacy development token = %#v, %v", claims, err)
	}
}
