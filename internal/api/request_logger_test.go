package api

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSanitizedRequestLoggerDoesNotLogOAuthSecrets(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	handler := sanitizedRequestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet,
		"https://vpn.example.test/extension/callback?code=secret-code&state=secret-state", nil)
	handler.ServeHTTP(httptest.NewRecorder(), request.WithContext(context.Background()))

	logged := output.String()
	for _, secret := range []string{"secret-code", "secret-state", "?code=", "vpn.example.test"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("request log contains sensitive value %q: %s", secret, logged)
		}
	}
	for _, expected := range []string{"method=GET", "path=/extension/callback", "status=204"} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("request log is missing %q: %s", expected, logged)
		}
	}
}
