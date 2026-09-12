package httpx

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReadBodyRejectsOversizedResponse(t *testing.T) {
	body, err := ReadBody(strings.NewReader("12345"), 4)
	if !errors.Is(err, ErrResponseTooLarge) || body != nil {
		t.Fatalf("ReadBody() = %q, %v; want nil, ErrResponseTooLarge", body, err)
	}
	body, err = ReadBody(bytes.NewBufferString("1234"), 4)
	if err != nil || string(body) != "1234" {
		t.Fatalf("ReadBody() exact limit = %q, %v", body, err)
	}
}

func TestClientWithAdditionalCAPreservesPrivateTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	caPath := t.TempDir() + "/management-ca.pem"
	certificate := server.Certificate()
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(caPath, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClientWithAdditionalCA(5*time.Second, caPath)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("private CA request failed: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.StatusCode)
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("minimum TLS version = %#x, want TLS 1.3", transport.TLSClientConfig.MinVersion)
	}
}

func TestClientWithAdditionalCARejectsInvalidInput(t *testing.T) {
	caPath := t.TempDir() + "/invalid.pem"
	if err := os.WriteFile(caPath, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientWithAdditionalCA(time.Second, caPath); err == nil {
		t.Fatal("invalid management CA was accepted")
	}
}

func TestHTTPConfigurationsAreBounded(t *testing.T) {
	client := NewClient(12 * time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || client.Timeout != 12*time.Second {
		t.Fatalf("unexpected client configuration: %#v", client)
	}
	if transport.DialContext == nil || transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 || transport.IdleConnTimeout <= 0 {
		t.Fatalf("incomplete transport timeouts: %#v", transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion == 0 || transport.MaxResponseHeaderBytes != MaxHeaderBytes {
		t.Fatalf("incomplete transport security limits: %#v", transport)
	}
	if !errors.Is(client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) {
		t.Fatal("dedicated client follows redirects")
	}

	api := NewAPIServer(":0", http.NotFoundHandler())
	if api.ReadHeaderTimeout <= 0 || api.ReadTimeout <= 0 || api.WriteTimeout <= 0 || api.IdleTimeout <= 0 || api.MaxHeaderBytes != MaxHeaderBytes {
		t.Fatalf("incomplete API server limits: %#v", api)
	}

	tunnel := NewTunnelServer(":0", http.NotFoundHandler())
	if tunnel.ReadHeaderTimeout <= 0 || tunnel.IdleTimeout <= 0 || tunnel.MaxHeaderBytes != MaxHeaderBytes {
		t.Fatalf("incomplete tunnel server limits: %#v", tunnel)
	}
	if tunnel.ReadTimeout != 0 || tunnel.WriteTimeout != 0 {
		t.Fatalf("tunnel lifetime was bounded: read=%s write=%s", tunnel.ReadTimeout, tunnel.WriteTimeout)
	}
}

func TestRemoteErrorDoesNotFormatProviderCause(t *testing.T) {
	err := NewRemoteError("jwks", "response_invalid", http.StatusBadGateway, 42, errors.New("provider-secret"))
	if strings.Contains(err.Error(), "provider-secret") {
		t.Fatalf("RemoteError leaked cause: %q", err.Error())
	}
	if !errors.Is(err, err.cause) {
		t.Fatal("RemoteError does not preserve error identity")
	}
}
