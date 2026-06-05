package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goastian/midori-vpn-core/internal/config"
)

func newOAuthTestHandler(tokenServerURL string) *OAuthHandler {
	return NewOAuthHandler(&config.Config{
		CORSAllowedOrigins:    "https://vpn.test",
		PublicBaseURL:         "https://vpn.test",
		ExtensionCallbackPath: "/extension/callback",
		AuthentikIssuer:       tokenServerURL + "/application/o/midori-vpn",
		AuthentikClientID:     "test-client",
		AuthentikClientSecret: "test-secret",
	}, nil)
}

func decodeJSONMap(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal response: %v\nbody=%s", err, rr.Body.String())
	}
	return body
}

func assertTokenForm(t *testing.T, r *http.Request, want url.Values) {
	t.Helper()

	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	for key, wantValues := range want {
		if got := r.Form.Get(key); got != wantValues[0] {
			t.Fatalf("form[%s] = %q, want %q", key, got, wantValues[0])
		}
	}
}

func TestOAuthCallbackSuccess(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/application/o/token/" {
			t.Fatalf("token path = %q", r.URL.Path)
		}
		assertTokenForm(t, r, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"auth-code"},
			"redirect_uri":  {"https://vpn.test/extension/callback"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
			"code_verifier": {"pkce-verifier"},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Authentik-Id", "req-callback-ok")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}))
	defer tokenServer.Close()

	handler := newOAuthTestHandler(tokenServer.URL)
	body := `{"code":"auth-code","redirect_uri":"https://vpn.test/extension/callback","code_verifier":"pkce-verifier"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/callback", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Callback(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	got := decodeJSONMap(t, rr)
	if got["ok"] != true {
		t.Fatalf("ok = %v, want true", got["ok"])
	}
	data := got["data"].(map[string]any)
	if data["access_token"] != "access-token" {
		t.Fatalf("access_token = %v", data["access_token"])
	}
}

func TestOAuthRefreshSuccess(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertTokenForm(t, r, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"refresh-token"},
			"client_id":     {"test-client"},
			"client_secret": {"test-secret"},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Authentik-Id", "req-refresh-ok")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "new-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   1800,
		})
	}))
	defer tokenServer.Close()

	handler := newOAuthTestHandler(tokenServer.URL)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"refresh-token"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://vpn.test")
	rr := httptest.NewRecorder()

	handler.Refresh(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	got := decodeJSONMap(t, rr)
	data := got["data"].(map[string]any)
	if data["access_token"] != "new-access-token" {
		t.Fatalf("access_token = %v", data["access_token"])
	}
}

func TestOAuthRefreshAuthentikErrorPassThrough(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Authentik-Id", "req-refresh-400")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","request_id":"req-refresh-400"}`))
	}))
	defer tokenServer.Close()

	handler := newOAuthTestHandler(tokenServer.URL)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(`{"refresh_token":"bad-refresh-token"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://vpn.test")
	rr := httptest.NewRecorder()

	handler.Refresh(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if got := rr.Body.String(); got != `{"error":"invalid_grant","request_id":"req-refresh-400"}` {
		t.Fatalf("body = %q", got)
	}
	if got := rr.Header().Get("Retry-After"); got != "" {
		t.Fatalf("Retry-After = %q, want empty", got)
	}
}

func TestOAuthAllowedOriginsIncludeLegacyDesktopWhenConfigured(t *testing.T) {
	handler := NewOAuthHandler(&config.Config{
		CORSAllowedOrigins: "https://vpn.astian.org,https://app.astian.org",
		PublicBaseURL:      "https://vpn.astian.org",
	}, nil)

	if !handler.isAllowedOrigin("https://app.astian.org") {
		t.Fatal("legacy desktop origin should be allowed when configured")
	}
	if handler.isAllowedOrigin("https://evil.example") {
		t.Fatal("unexpected external origin allowed")
	}
}

func TestOAuthAllowedOriginsSupportWildcardAstianSubdomains(t *testing.T) {
	handler := NewOAuthHandler(&config.Config{
		CORSAllowedOrigins: "https://*.astian.org",
		PublicBaseURL:      "https://vpn.astian.org",
	}, nil)

	if !handler.isAllowedOrigin("https://vpn.astian.org") {
		t.Fatal("wildcard Astian origin should be allowed")
	}
	if handler.isAllowedOrigin("http://vpn.astian.org") {
		t.Fatal("wildcard should not allow a different scheme")
	}
}

func TestOAuthCallbackUpstreamTimeoutReturnsRetryAfter(t *testing.T) {
	oldTimeout := authentikTokenExchangeTimeout
	authentikTokenExchangeTimeout = 25 * time.Millisecond
	t.Cleanup(func() { authentikTokenExchangeTimeout = oldTimeout })

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer tokenServer.Close()

	handler := newOAuthTestHandler(tokenServer.URL)
	body := `{"code":"auth-code","redirect_uri":"https://vpn.test/extension/callback","code_verifier":"pkce-verifier"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/callback", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.Callback(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d, body=%s", rr.Code, http.StatusBadGateway, rr.Body.String())
	}
	if got := rr.Header().Get("Retry-After"); got != "30" {
		t.Fatalf("Retry-After = %q, want 30", got)
	}
	got := decodeJSONMap(t, rr)
	if got["ok"] != false {
		t.Fatalf("ok = %v, want false", got["ok"])
	}
	if got["error"] != "auth provider temporarily unavailable; retry later" {
		t.Fatalf("error = %v", got["error"])
	}
}
