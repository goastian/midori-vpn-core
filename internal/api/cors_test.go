package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/config"
)

func corsRequest(t *testing.T, middleware func(http.Handler) http.Handler, method, path, origin string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Origin", origin)
	middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(recorder, request)
	return recorder
}

func TestCORSRejectsUnregisteredExtensionOutsideInitialPKCECallback(t *testing.T) {
	cfg := &config.Config{CORSAllowedOrigins: "https://vpn.example.test"}
	checker := func(context.Context, string) (bool, error) { return false, nil }
	middleware := CORSMiddleware(cfg, checker)

	response := corsRequest(t, middleware, http.MethodGet, "/api/v1/control/servers", "moz-extension://unregistered")
	if origin := response.Header().Get("Access-Control-Allow-Origin"); origin != "" {
		t.Fatalf("unregistered extension received CORS origin %q", origin)
	}
}

func TestCORSAllowsRegisteredAndConfiguredExtensionOrigins(t *testing.T) {
	cfg := &config.Config{
		CORSAllowedOrigins:      "https://vpn.example.test",
		AllowedExtensionOrigins: "chrome-extension://configured",
	}
	checker := func(_ context.Context, origin string) (bool, error) {
		return origin == "moz-extension://registered", nil
	}
	middleware := CORSMiddleware(cfg, checker)

	for _, origin := range []string{"chrome-extension://configured", "moz-extension://registered"} {
		response := corsRequest(t, middleware, http.MethodGet, "/api/v1/control/servers", origin)
		if got := response.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, origin)
		}
	}
}

func TestCORSAllowsOnlyInitialPKCECallbackForUnknownExtension(t *testing.T) {
	cfg := &config.Config{CORSAllowedOrigins: "https://vpn.example.test"}
	middleware := CORSMiddleware(cfg)
	origin := "moz-extension://first-use"

	for _, method := range []string{http.MethodOptions, http.MethodPost} {
		response := corsRequest(t, middleware, method, "/api/v1/auth/callback", origin)
		if got := response.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Fatalf("%s callback CORS origin = %q, want %q", method, got, origin)
		}
	}
	response := corsRequest(t, middleware, http.MethodPost, "/api/v1/auth/refresh", origin)
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unknown extension was allowed on refresh: %q", got)
	}
}

func TestCORSFailsClosedOnTrustedOriginLookupError(t *testing.T) {
	cfg := &config.Config{CORSAllowedOrigins: "https://vpn.example.test"}
	checker := func(context.Context, string) (bool, error) { return false, errors.New("database unavailable") }
	response := corsRequest(t, CORSMiddleware(cfg, checker), http.MethodGet, "/api/v1/control/servers", "chrome-extension://registered")
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("lookup failure allowed extension origin: %q", got)
	}
}

func TestBrowserExtensionOriginRequiresAnExactOrigin(t *testing.T) {
	for _, rejected := range []string{
		"moz-extension://",
		"moz-extension://id/path",
		"chrome-extension://id?query=1",
		"https://extension.example.test",
	} {
		if isBrowserExtensionOrigin(rejected) {
			t.Fatalf("malformed extension origin accepted: %q", rejected)
		}
	}
}
