package control

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthLogoutRevokesAtProviderOrigin(t *testing.T) {
	for _, issuerPath := range []string{"", "/application/o/midori-vpn", "/application/o/midori-vpn/"} {
		t.Run("issuer"+issuerPath, func(t *testing.T) {
			type providerRequest struct {
				method string
				path   string
				form   url.Values
			}
			received := make(chan providerRequest, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				received <- providerRequest{method: r.Method, path: r.URL.Path, form: r.Form}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			handler := newOAuthTestHandler(server.URL)
			handler.cfg.AuthentikIssuer = server.URL + issuerPath
			request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", strings.NewReader(`{"access_token":"logout-access","refresh_token":"logout-refresh"}`))
			request.Header.Set("Origin", "https://vpn.test")
			recorder := httptest.NewRecorder()
			handler.Logout(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("logout status = %d", recorder.Code)
			}
			select {
			case got := <-received:
				if got.method != http.MethodPost || got.path != "/application/o/revoke-token/" {
					t.Fatalf("revocation request = %s %s", got.method, got.path)
				}
				for key, want := range map[string]string{
					"token": "logout-refresh", "token_type_hint": "refresh_token",
					"client_id": "test-client", "client_secret": "test-secret",
				} {
					if got.form.Get(key) != want {
						t.Fatalf("unexpected revocation form field %q", key)
					}
				}
			case <-time.After(3 * time.Second):
				t.Fatal("provider did not receive the revocation request")
			}
		})
	}
}
