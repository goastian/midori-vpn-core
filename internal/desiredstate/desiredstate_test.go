package desiredstate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type limitRecorder struct{ value int }

func (r *limitRecorder) ApplyPeerLimit(value int, commit func() error) error {
	if commit != nil {
		if err := commit(); err != nil {
			return err
		}
	}
	r.value = value
	return nil
}

func TestCanonicalSignVerifyAndStoredRecord(t *testing.T) {
	signer, verifier := testSignerVerifier(t)
	bundle := Normalize(testBundle(time.Now().UTC()))
	bundle.PublicEndpoints = []PublicEndpoint{
		{Name: "wss", Host: "WSS.EXAMPLE.TEST", Port: 443},
		{Name: "wg", Host: "2001:db8::1", Port: 51820},
	}
	bundle.Transports = []Transport{
		{Protocol: "wss", Enabled: false, Endpoint: "wss", Priority: 20},
		{Protocol: "wireguard", Enabled: true, Endpoint: "wg", Priority: 10},
	}
	signed, payload, digest, err := signer.Sign(bundle)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.Verify(*signed, bundle.NodeID, "2.1.0", time.Now().UTC(), false)
	if err != nil || !bytes.Equal(verified, payload) {
		t.Fatalf("verify = %q, %v", verified, err)
	}
	if signed.Bundle.PublicEndpoints[0].Name != "wg" || signed.Bundle.Transports[0].Protocol != "wireguard" {
		t.Fatalf("bundle was not normalized: %#v", signed.Bundle)
	}
	rawSignature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	restored, err := DecodeStored(payload, digest, rawSignature, signed.SigningKeyID)
	if err != nil || restored.Signature != signed.Signature {
		t.Fatalf("DecodeStored = %#v, %v", restored, err)
	}
}

func TestVerifierRejectsTamperTargetExpiryVersionAndTrust(t *testing.T) {
	signer, verifier := testSignerVerifier(t)
	now := time.Now().UTC().Truncate(time.Second)
	bundle := testBundle(now)
	signed, _, _, err := signer.Sign(bundle)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		edit    func(*SignedBundle)
		node    uuid.UUID
		version string
		now     time.Time
		want    error
	}{
		{"tamper", func(s *SignedBundle) { s.Bundle.Capacity.MaxPeers++ }, bundle.NodeID, "2.0.0", now, ErrInvalidSignature},
		{"target", func(*SignedBundle) {}, uuid.New(), "2.0.0", now, ErrWrongTarget},
		{"expired", func(*SignedBundle) {}, bundle.NodeID, "2.0.0", bundle.ExpiresAt, ErrExpired},
		{"future", func(*SignedBundle) {}, bundle.NodeID, "2.0.0", bundle.IssuedAt.Add(-time.Minute), ErrNotYetValid},
		{"version", func(*SignedBundle) {}, bundle.NodeID, "1.9.9", now, ErrIncompatibleVersion},
		{"key", func(s *SignedBundle) { s.SigningKeyID = "unknown" }, bundle.NodeID, "2.0.0", now, ErrUntrustedSigningKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := *signed
			test.edit(&candidate)
			if _, err := verifier.Verify(candidate, test.node, test.version, test.now, false); !errors.Is(err, test.want) {
				t.Fatalf("error = %v; want %v", err, test.want)
			}
		})
	}
}

func TestValidateRejectsNonCanonicalRepresentation(t *testing.T) {
	bundle := Normalize(testBundle(time.Now().UTC()))
	bundle.PublicEndpoints[0].Name = "WG"
	if err := Validate(bundle); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("non-canonical bundle error = %v", err)
	}
}

func TestActivatorPreservesAtomicLastKnownGoodAndRevisionChain(t *testing.T) {
	signer, verifierText := testSignerAndTrust(t)
	now := time.Now().UTC().Truncate(time.Second)
	limits := &limitRecorder{}
	local := LocalCapabilities{Transports: map[string]bool{"wireguard": true}}
	activator, err := NewActivator(t.TempDir(), testNodeID, "2.0.0", verifierText, local, limits)
	if err != nil {
		t.Fatal(err)
	}
	activator.now = func() time.Time { return now }
	first, _, _, _ := signer.Sign(testBundle(now))
	if err := activator.Apply(*first); err != nil {
		t.Fatal(err)
	}
	if limits.value != 100 || activator.Snapshot().AppliedRevision == nil || *activator.Snapshot().AppliedRevision != 1 {
		t.Fatalf("unexpected activation: limit=%d snapshot=%#v", limits.value, activator.Snapshot())
	}
	if err := activator.Apply(*first); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	previous := int64(1)
	secondBundle := testBundle(now)
	secondBundle.Revision = 2
	secondBundle.PreviousRevision = &previous
	secondBundle.Capacity.MaxPeers = 75
	second, _, _, _ := signer.Sign(secondBundle)
	if err := activator.Apply(*second); err != nil || limits.value != 75 {
		t.Fatalf("second apply: limit=%d err=%v", limits.value, err)
	}
	if err := activator.Apply(*first); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback error = %v", err)
	}
	gapPrevious := int64(3)
	gapBundle := testBundle(now)
	gapBundle.Revision = 4
	gapBundle.PreviousRevision = &gapPrevious
	gap, _, _, _ := signer.Sign(gapBundle)
	if err := activator.Apply(*gap); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("gap error = %v", err)
	}
	path := filepath.Join(activator.stateDir, "desired-state.json")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("last-known-good permissions = %v, %v", info, err)
	}
	restartedLimits := &limitRecorder{}
	restarted, _ := NewActivator(activator.stateDir, testNodeID, "2.0.0", verifierText, local, restartedLimits)
	restarted.now = func() time.Time { return second.Bundle.ExpiresAt.Add(time.Hour) }
	if err := restarted.LoadLastKnownGood(); err != nil || restartedLimits.value != 75 {
		t.Fatalf("expired last-known-good load: limit=%d err=%v", restartedLimits.value, err)
	}
}

func TestActivatorRejectsUnavailableLocalCapability(t *testing.T) {
	signer, trust := testSignerAndTrust(t)
	now := time.Now().UTC().Truncate(time.Second)
	bundle := testBundle(now)
	bundle.SecretReferences = []SecretReference{{Name: "tls", FingerprintSHA256: string(bytes.Repeat([]byte{'a'}, 64))}}
	bundle.Transports[0].SecretReferences = []string{"tls"}
	signed, _, _, err := signer.Sign(bundle)
	if err != nil {
		t.Fatal(err)
	}
	activator, _ := NewActivator(t.TempDir(), testNodeID, "2.0.0", trust,
		LocalCapabilities{Transports: map[string]bool{"wireguard": true}}, &limitRecorder{})
	if err := activator.Apply(*signed); !errors.Is(err, ErrLocalCapability) {
		t.Fatalf("local capability error = %v", err)
	}
}

func TestActivatorRejectsDesiredStateForAnotherConfiguredCluster(t *testing.T) {
	signer, trust := testSignerAndTrust(t)
	bundle := testBundle(time.Now().UTC().Truncate(time.Second))
	signed, _, _, err := signer.Sign(bundle)
	if err != nil {
		t.Fatal(err)
	}
	activator, err := NewActivator(t.TempDir(), testNodeID, "2.0.0", trust,
		LocalCapabilities{ClusterID: uuid.New(), Transports: map[string]bool{"wireguard": true}}, &limitRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := activator.Apply(*signed); !errors.Is(err, ErrLocalCapability) {
		t.Fatalf("wrong local cluster error = %v", err)
	}
}

func TestActivatorAcceptsExplicitExternalGatewayCapability(t *testing.T) {
	signer, trust := testSignerAndTrust(t)
	bundle := testBundle(time.Now().UTC().Truncate(time.Second))
	bundle.PublicEndpoints = append(bundle.PublicEndpoints,
		PublicEndpoint{Name: "openvpn", Host: "vpn.example.test", Port: 1194})
	bundle.Transports = append(bundle.Transports,
		Transport{Protocol: "openvpn", Enabled: true, Priority: 20, Endpoint: "openvpn"})
	signed, _, _, err := signer.Sign(bundle)
	if err != nil {
		t.Fatal(err)
	}
	transports, err := ParseExternalTransports("openvpn")
	if err != nil {
		t.Fatal(err)
	}
	transports["wireguard"] = true
	activator, err := NewActivator(t.TempDir(), testNodeID, "2.0.0", trust,
		LocalCapabilities{Transports: transports}, &limitRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := activator.Apply(*signed); err != nil {
		t.Fatalf("apply desired state with declared external gateway: %v", err)
	}
}

var (
	testNodeID    = uuid.MustParse("33333333-3333-4333-8333-333333333333")
	testClusterID = uuid.MustParse("44444444-4444-4444-8444-444444444444")
)

func testBundle(now time.Time) Bundle {
	return Bundle{
		SchemaVersion: SchemaVersion, ClusterID: testClusterID, NodeID: testNodeID,
		Revision: 1, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute),
		MinimumCoreVersion: "2.0.0", ManagementEndpoint: "https://control.example.test",
		PublicEndpoints:  []PublicEndpoint{{Name: "wg", Host: "vpn.example.test", Port: 51820}},
		Capacity:         Capacity{MaxPeers: 100},
		Transports:       []Transport{{Protocol: "wireguard", Enabled: true, Priority: 10, Endpoint: "wg"}},
		SecretReferences: []SecretReference{},
	}
}

func testSignerVerifier(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	signer, trust := testSignerAndTrust(t)
	verifier, err := NewVerifier(trust)
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

func testSignerAndTrust(t *testing.T) (*Signer, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPrivate := base64.RawURLEncoding.EncodeToString(privateKey)
	signer, err := NewSigner("control-2026", encodedPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return signer, "control-2026=" + base64.RawURLEncoding.EncodeToString(publicKey)
}

func TestDecodeStoredRejectsDigestAndUnknownFields(t *testing.T) {
	signer, _ := testSignerVerifier(t)
	signed, payload, digest, err := signer.Sign(testBundle(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	digest[0] ^= 1
	if _, err := DecodeStored(payload, digest, signature, signed.SigningKeyID); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("digest error = %v", err)
	}
	var object map[string]any
	_ = json.Unmarshal(payload, &object)
	object["unknown"] = true
	withUnknown, _ := json.Marshal(object)
	wantDigest := sha256.Sum256(withUnknown)
	if _, err := DecodeStored(withUnknown, wantDigest[:], signature, signed.SigningKeyID); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestSignerRejectsInconsistentExpandedPrivateKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKey[len(privateKey)-1] ^= 1
	if _, err := NewSigner("control-test", base64.RawURLEncoding.EncodeToString(privateKey)); err == nil {
		t.Fatal("inconsistent expanded private key was accepted")
	}
}

func TestSecretFingerprintsRequireCanonicalUniqueEntries(t *testing.T) {
	fingerprint := string(bytes.Repeat([]byte{'a'}, 64))
	parsed, err := ParseSecretFingerprints("tls=" + fingerprint)
	if err != nil || parsed["tls"] != fingerprint {
		t.Fatalf("canonical fingerprints = %#v, %v", parsed, err)
	}
	for _, value := range []string{"TLS=" + fingerprint, "tls=" + strings.ToUpper(fingerprint), "tls=" + fingerprint + ",tls=" + fingerprint} {
		if _, err := ParseSecretFingerprints(value); err == nil {
			t.Fatalf("non-canonical fingerprint %q accepted", value)
		}
	}
}

func TestExternalTransportsRequireExplicitGatewayProtocols(t *testing.T) {
	parsed, err := ParseExternalTransports("openvpn,ikev2")
	if err != nil || !parsed["openvpn"] || !parsed["ikev2"] || len(parsed) != 2 {
		t.Fatalf("external transports = %#v, %v", parsed, err)
	}
	for _, value := range []string{"OpenVPN", "wireguard", "openvpn,openvpn", "openvpn,proxy"} {
		if _, err := ParseExternalTransports(value); err == nil {
			t.Fatalf("invalid external transports %q accepted", value)
		}
	}
	empty, err := ParseExternalTransports("")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty external transports = %#v, %v", empty, err)
	}
}
