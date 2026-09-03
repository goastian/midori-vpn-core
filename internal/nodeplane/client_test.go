package nodeplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/desiredstate"
	"github.com/goastian/midori-vpn-core/internal/fleetauth"
	"github.com/goastian/midori-vpn-core/internal/wg"
)

func TestEnrollSignsRequestAndDestroysConsumedToken(t *testing.T) {
	identity := testIdentity(t)
	token := randomToken(t)
	tokenPath := writeToken(t, token)
	verifier := fleetauth.NewVerifier(fleetauth.NewMemoryReplayStore())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q", got)
		}
		if err := verifier.Verify(r.Context(), r, body, identity.NodeID(), identity.PublicKey()); err != nil {
			t.Errorf("signed enrollment request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, identity, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.EnrollFromTokenFile(context.Background(), tokenPath); err != nil {
		t.Fatalf("EnrollFromTokenFile: %v", err)
	}
	if _, err := os.Lstat(tokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("consumed enrollment token still exists: %v", err)
	}
}

func TestEnrollPreservesTokenWhenControlRejectsRequest(t *testing.T) {
	identity := testIdentity(t)
	token := randomToken(t)
	tokenPath := writeToken(t, token)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("provider-secret-must-not-leak"))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, identity, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	err = client.EnrollFromTokenFile(context.Background(), tokenPath)
	if err == nil {
		t.Fatal("expected rejected enrollment")
	}
	if strings.Contains(err.Error(), "provider-secret") || strings.Contains(err.Error(), token) {
		t.Fatalf("error leaked sensitive response content: %v", err)
	}
	if _, statErr := os.Stat(tokenPath); statErr != nil {
		t.Fatalf("token was removed after failed enrollment: %v", statErr)
	}
}

func TestHeartbeatSignsExactPayload(t *testing.T) {
	identity := testIdentity(t)
	verifier := fleetauth.NewVerifier(fleetauth.NewMemoryReplayStore())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := verifier.Verify(r.Context(), r, body, identity.NodeID(), identity.PublicKey()); err != nil {
			t.Errorf("signed heartbeat: %v", err)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("heartbeat unexpectedly included enrollment bearer token")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, identity, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Heartbeat(context.Background(), HeartbeatRequest{
		SchemaVersion: SchemaVersion,
		CoreVersion:   "2.0.0",
		HealthStatus:  "healthy",
		MaxPeers:      100,
		ReportedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
}

func TestFetchDesiredStateSignsEmptyGETAndDecodesBoundedEnvelope(t *testing.T) {
	identity := testIdentity(t)
	verifier := fleetauth.NewVerifier(fleetauth.NewMemoryReplayStore())
	bundle := desiredstate.SignedBundle{
		Bundle:       desiredstate.Bundle{NodeID: identity.NodeID(), Revision: 1},
		SigningKeyID: "control-test", Signature: strings.Repeat("a", 86),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != DesiredStatePath {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("desired state request body = %q", body)
		}
		if err := verifier.Verify(r.Context(), r, body, identity.NodeID(), identity.PublicKey()); err != nil {
			t.Errorf("signed desired state request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": bundle})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, identity, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	got, available, err := client.FetchDesiredState(context.Background())
	if err != nil || !available || got.Bundle.NodeID != identity.NodeID() || got.SigningKeyID != "control-test" {
		t.Fatalf("FetchDesiredState = %#v, %v, %v", got, available, err)
	}
}

func TestNewClientRejectsUnsafeControlURLs(t *testing.T) {
	identity := testIdentity(t)
	for _, rawURL := range []string{
		"http://control.test", "https://user@control.test", "https://control.test/path",
		"https://control.test?query=1", "https://control.test#fragment", "control.test",
	} {
		t.Run(rawURL, func(t *testing.T) {
			if _, err := NewClient(rawURL, identity, nil, false); err == nil {
				t.Fatalf("expected %q to be rejected", rawURL)
			}
		})
	}
}

func TestReporterSendsBoundedHealthWithoutClaimingCertification(t *testing.T) {
	identity := testIdentity(t)
	var got HeartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, identity, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	provider := stubStatsProvider{stats: &wg.ServerStatsResponse{PeerCount: 8}}
	reporter, err := NewReporter(client, provider, "2.0.0", 4, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.report(context.Background())
	if got.CurrentPeers != 8 || got.MaxPeers != 8 {
		t.Fatalf("reported peers = %d/%d; want 8/8", got.CurrentPeers, got.MaxPeers)
	}
	if got.TransportStates["wireguard"].Certified {
		t.Fatal("reporter claimed WireGuard certification")
	}
}

func TestReporterConvertsStatsFailureToSafeHealthCode(t *testing.T) {
	identity := testIdentity(t)
	var got HeartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, identity, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := NewReporter(client, stubStatsProvider{err: errors.New("wireguard-provider-secret")}, "2.0.0", 100, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.report(context.Background())
	if got.HealthStatus != "error" || got.LastErrorCode != "core_peer_state_unavailable" {
		t.Fatalf("health = %q/%q", got.HealthStatus, got.LastErrorCode)
	}
	if strings.Contains(got.LastErrorCode, "provider-secret") {
		t.Fatal("heartbeat leaked the provider error")
	}
}

func TestReporterAppliesDesiredStateBeforeReportingObservedRevision(t *testing.T) {
	identity := testIdentity(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := desiredstate.NewSigner("control-test", base64.RawURLEncoding.EncodeToString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	bundle := desiredstate.Bundle{
		SchemaVersion: desiredstate.SchemaVersion, ClusterID: uuid.New(), NodeID: identity.NodeID(), Revision: 1,
		IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), MinimumCoreVersion: "2.0.0",
		ManagementEndpoint: "https://control.test",
		PublicEndpoints: []desiredstate.PublicEndpoint{
			{Name: "wg", Host: "vpn.test", Port: 51820},
			{Name: "wss", Host: "wss.test", Port: 443},
		},
		Capacity: desiredstate.Capacity{MaxPeers: 23},
		Transports: []desiredstate.Transport{
			{Protocol: "wireguard", Enabled: true, Endpoint: "wg", Priority: 10},
			{Protocol: "wss", Enabled: false, Endpoint: "wss", Priority: 20},
		},
		SecretReferences: []desiredstate.SecretReference{},
	}
	signed, _, _, err := signer.Sign(bundle)
	if err != nil {
		t.Fatal(err)
	}
	requestVerifier := fleetauth.NewVerifier(fleetauth.NewMemoryReplayStore())
	var heartbeat HeartbeatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := requestVerifier.Verify(r.Context(), r, body, identity.NodeID(), identity.PublicKey()); err != nil {
			t.Errorf("node request signature: %v", err)
		}
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": signed})
			return
		}
		if err := json.Unmarshal(body, &heartbeat); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, identity, server.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	limiter := &testPeerLimiter{}
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	activator, err := desiredstate.NewActivator(
		stateDir, identity.NodeID(), "2.0.0",
		"control-test="+base64.RawURLEncoding.EncodeToString(publicKey),
		desiredstate.LocalCapabilities{Transports: map[string]bool{"wireguard": true}}, limiter,
	)
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := NewReporter(client, stubStatsProvider{stats: &wg.ServerStatsResponse{PeerCount: 2}}, "2.0.0", 100, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.SetDesiredState(activator)
	reporter.report(context.Background())
	if heartbeat.AppliedRevision == nil || *heartbeat.AppliedRevision != 1 || !heartbeat.VersionCompatible || heartbeat.MaxPeers != 23 {
		t.Fatalf("heartbeat desired state = %#v", heartbeat)
	}
	if heartbeat.TransportStates["wireguard"].Certified {
		t.Fatal("reporter copied desired certification into observed state")
	}
	if heartbeat.TransportStates["wss"].Status != "disabled" {
		t.Fatalf("disabled desired transport = %#v", heartbeat.TransportStates["wss"])
	}
}

func testIdentity(t *testing.T) *fleetauth.Identity {
	t.Helper()
	identity, err := fleetauth.LoadOrCreateIdentity(filepath.Join(t.TempDir(), "state"), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func randomToken(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func writeToken(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enrollment.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type stubStatsProvider struct {
	stats *wg.ServerStatsResponse
	err   error
}

type testPeerLimiter struct{ value int }

func (l *testPeerLimiter) ApplyPeerLimit(value int, commit func() error) error {
	if commit != nil {
		if err := commit(); err != nil {
			return err
		}
	}
	l.value = value
	return nil
}

func (s stubStatsProvider) ServerStats() (*wg.ServerStatsResponse, error) {
	return s.stats, s.err
}
