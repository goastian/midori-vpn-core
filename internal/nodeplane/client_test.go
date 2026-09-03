package nodeplane

import (
	"context"
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

func (s stubStatsProvider) ServerStats() (*wg.ServerStatsResponse, error) {
	return s.stats, s.err
}
