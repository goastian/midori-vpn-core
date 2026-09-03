package fleetauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIdentityPersistsWithPrivatePermissions(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "node-state")
	nodeID := uuid.New()
	first, err := LoadOrCreateIdentity(stateDir, nodeID)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity first call: %v", err)
	}
	second, err := LoadOrCreateIdentity(stateDir, nodeID)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity second call: %v", err)
	}
	if first.EncodedPublicKey() != second.EncodedPublicKey() {
		t.Fatal("node identity changed between loads")
	}
	assertMode(t, stateDir, 0o700)
	assertMode(t, filepath.Join(stateDir, "identity.json"), 0o600)
	assertMode(t, filepath.Join(stateDir, ".identity.lock"), 0o600)

	if _, err := LoadOrCreateIdentity(stateDir, uuid.New()); err == nil {
		t.Fatal("expected configured node mismatch to fail closed")
	}
}

func TestIdentityConcurrentCreationUsesOneKey(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "node-state")
	nodeID := uuid.New()
	const callers = 8
	keys := make(chan string, callers)
	errs := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			identity, err := LoadOrCreateIdentity(stateDir, nodeID)
			if err != nil {
				errs <- err
				return
			}
			keys <- identity.EncodedPublicKey()
		}()
	}
	group.Wait()
	close(keys)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent LoadOrCreateIdentity: %v", err)
	}
	var expected string
	for key := range keys {
		if expected == "" {
			expected = key
		}
		if key != expected {
			t.Fatal("concurrent identity creation returned distinct keys")
		}
	}
}

func TestIdentityRejectsExposedOrLinkedFiles(t *testing.T) {
	nodeID := uuid.New()
	stateDir := filepath.Join(t.TempDir(), "state")
	if _, err := LoadOrCreateIdentity(stateDir, nodeID); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	identityPath := filepath.Join(stateDir, "identity.json")
	if err := os.Chmod(identityPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateIdentity(stateDir, nodeID); err == nil {
		t.Fatal("expected exposed identity permissions to be rejected")
	}

	linkedDir := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(stateDir, linkedDir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateIdentity(linkedDir, nodeID); err == nil {
		t.Fatal("expected symlink state directory to be rejected")
	}
}

func TestSignedRequestVerificationAndReplayProtection(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.New()
	now := time.Unix(1_800_000_000, 0).UTC()
	requestURL, _ := url.Parse("https://control.test/api/v1/node/heartbeat?revision=2")
	req := &http.Request{Method: http.MethodPost, URL: requestURL, Header: make(http.Header)}
	body := []byte(`{"schema_version":1}`)
	if err := signRequest(req, body, nodeID, privateKey, now); err != nil {
		t.Fatalf("signRequest: %v", err)
	}
	verifier := NewVerifier(NewMemoryReplayStore())
	verifier.now = func() time.Time { return now }
	if err := verifier.Verify(context.Background(), req, body, nodeID, publicKey); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := verifier.Verify(context.Background(), req, body, nodeID, publicKey); err == nil {
		t.Fatal("expected replay to be rejected")
	}

	tampered := req.Clone(context.Background())
	tampered.Header = req.Header.Clone()
	if err := verifier.Verify(context.Background(), tampered, []byte(`{"schema_version":2}`), nodeID, publicKey); err == nil {
		t.Fatal("expected tampered body to be rejected")
	}
	wrongNode := req.Clone(context.Background())
	wrongNode.Header = req.Header.Clone()
	if err := verifier.Verify(context.Background(), wrongNode, body, uuid.New(), publicKey); err == nil {
		t.Fatal("expected node mismatch to be rejected")
	}
}

func TestSignedRequestRejectsExpiredAndUnavailableReplayStore(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.New()
	now := time.Unix(1_800_000_000, 0).UTC()
	req, _ := http.NewRequest(http.MethodPost, "https://control.test/api/v1/node/heartbeat", nil)
	if err := signRequest(req, nil, nodeID, privateKey, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifier(NewMemoryReplayStore())
	verifier.now = func() time.Time { return now }
	if err := verifier.Verify(context.Background(), req, nil, nodeID, publicKey); err == nil {
		t.Fatal("expected expired signature to be rejected")
	}

	req, _ = http.NewRequest(http.MethodPost, "https://control.test/api/v1/node/heartbeat", nil)
	if err := signRequest(req, nil, nodeID, privateKey, now); err != nil {
		t.Fatal(err)
	}
	verifier = NewVerifier(errorReplayStore{})
	verifier.now = func() time.Time { return now }
	if err := verifier.Verify(context.Background(), req, nil, nodeID, publicKey); !errors.Is(err, ErrReplayProtectionUnavailable) {
		t.Fatalf("replay store error = %v; want ErrReplayProtectionUnavailable", err)
	}
}

func TestEnrollmentTokenReadAndDestroy(t *testing.T) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := rawURL(tokenBytes)
	path := filepath.Join(t.TempDir(), "enrollment.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadEnrollmentToken(path)
	if err != nil || got != token {
		t.Fatalf("ReadEnrollmentToken = %q, %v", got, err)
	}
	if err := DestroyEnrollmentToken(path, token); err != nil {
		t.Fatalf("DestroyEnrollmentToken: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token still exists after destruction: %v", err)
	}
}

func TestEnrollmentTokenRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(rawURL(make([]byte, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnrollmentToken(link); err == nil {
		t.Fatal("expected token symlink to be rejected")
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnrollmentToken(target); err == nil {
		t.Fatal("expected exposed token permissions to be rejected")
	}
}

func TestEnrollmentTokenDestructionRejectsChangedCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment.token")
	current := rawURL(make([]byte, 32))
	if err := os.WriteFile(path, []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DestroyEnrollmentToken(path, rawURL(bytes.Repeat([]byte{1}, 32))); err == nil {
		t.Fatal("expected changed enrollment token to be preserved")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != current {
		t.Fatalf("changed token was modified: %q, %v", contents, err)
	}
}

func assertMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual := info.Mode().Perm(); actual != expected {
		t.Fatalf("%s mode = %o; want %o", path, actual, expected)
	}
}

func rawURL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

type errorReplayStore struct{}

func (errorReplayStore) Use(context.Context, uuid.UUID, string, time.Duration) (bool, error) {
	return false, errors.New("replay store unavailable")
}
