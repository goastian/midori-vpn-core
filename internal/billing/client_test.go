package billing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/httpx"
	"github.com/google/uuid"
)

func TestEntitlementsResponseIsStrictlyBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", httpx.MaxResponseBytes+1)))
	}))
	defer server.Close()

	client := NewClient(&config.Config{AstianPaymentURL: server.URL}, nil)
	_, err := client.fetchFromAstianPayment(context.Background(), uuid.New(), "authentik-user")
	var remoteErr *httpx.RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Code != "response_too_large" {
		t.Fatalf("fetchFromAstianPayment() error = %#v", err)
	}
}
