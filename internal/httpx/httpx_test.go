package httpx

import (
	"bytes"
	"errors"
	"net/http"
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
