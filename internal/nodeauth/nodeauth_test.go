package nodeauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func testIdentity(t *testing.T) (*Signer, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner("control-1", base64.RawURLEncoding.EncodeToString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	return signer, "control-1=" + base64.RawURLEncoding.EncodeToString(publicKey)
}

func TestRedisRegistrySharesReplayAndRevocation(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	bootstrapSigner, bootstrapKey := testIdentity(t)
	_ = bootstrapSigner
	verifierOne, err := NewVerifier(bootstrapKey, "", redisURL)
	if err != nil {
		t.Fatal(err)
	}
	verifierTwo, err := NewVerifier(bootstrapKey, "", redisURL)
	if err != nil {
		t.Fatal(err)
	}
	defer verifierOne.Close()
	defer verifierTwo.Close()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "integration-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	encoding := base64.RawURLEncoding
	if err := verifierOne.Register(t.Context(), nodeID, encoding.EncodeToString(publicKey)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		verifierOne.redis.HDel(t.Context(), "nodeauth:public-keys", nodeID)
		verifierOne.redis.SRem(t.Context(), "nodeauth:revoked", nodeID)
	})
	signer, err := NewSigner(nodeID, encoding.EncodeToString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://core.example.test/api/v1/stats", nil)
	if err := signer.Sign(req, nil); err != nil {
		t.Fatal(err)
	}
	if err := verifierOne.Verify(t.Context(), req, nil); err != nil {
		t.Fatalf("registered identity rejected: %v", err)
	}
	if err := verifierTwo.Verify(t.Context(), req, nil); err == nil {
		t.Fatal("shared replay cache accepted a duplicate request")
	}

	if err := verifierOne.Revoke(t.Context(), nodeID); err != nil {
		t.Fatal(err)
	}
	newRequest, _ := http.NewRequest(http.MethodGet, "https://core.example.test/api/v1/stats", nil)
	if err := signer.Sign(newRequest, nil); err != nil {
		t.Fatal(err)
	}
	if err := verifierTwo.Verify(t.Context(), newRequest, nil); err == nil {
		t.Fatal("shared revocation did not take effect")
	}
}

func TestSignerVerifierAndReplayProtection(t *testing.T) {
	signer, publicKeys := testIdentity(t)
	verifier, err := NewVerifier(publicKeys, "", "")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"public_key":"test"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://core.example.test/api/v1/peers?mode=strict", bytes.NewReader(body))
	if err := signer.Sign(req, body); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(req.Context(), req, body); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := verifier.Verify(req.Context(), req, body); err == nil {
		t.Fatal("replayed request accepted")
	}
}

func TestVerifierRejectsTamperingExpiryAndRevocation(t *testing.T) {
	signer, publicKeys := testIdentity(t)
	newRequest := func() *http.Request {
		req, _ := http.NewRequest(http.MethodDelete, "https://core.example.test/api/v1/peers/key", nil)
		if err := signer.Sign(req, nil); err != nil {
			t.Fatal(err)
		}
		return req
	}

	verifier, _ := NewVerifier(publicKeys, "", "")
	if err := verifier.Verify(newRequest().Context(), newRequest(), []byte("tampered")); err == nil {
		t.Fatal("tampered body accepted")
	}

	expired := newRequest()
	verifier.now = func() time.Time { return time.Now().Add(maxClockSkew + time.Second) }
	if err := verifier.Verify(expired.Context(), expired, nil); err == nil {
		t.Fatal("expired request accepted")
	}

	revoked, _ := NewVerifier(publicKeys, "control-1", "")
	req := newRequest()
	if err := revoked.Verify(req.Context(), req, nil); err == nil {
		t.Fatal("revoked node accepted")
	}
}
