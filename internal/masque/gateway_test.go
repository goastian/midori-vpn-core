package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goastian/midori-vpn-core/internal/proxytoken"
	"github.com/google/uuid"
	masquego "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func TestTargetMatchesOnlyConfiguredWireGuardSocket(t *testing.T) {
	allowed := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51820}
	tests := []struct {
		target string
		want   bool
	}{
		{target: "127.0.0.1:51820", want: true},
		{target: "[::ffff:127.0.0.1]:51820", want: true},
		{target: "127.0.0.1:53", want: false},
		{target: "8.8.8.8:51820", want: false},
		{target: "localhost:51820", want: false},
		{target: "invalid", want: false},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			if got := targetMatches(test.target, allowed); got != test.want {
				t.Fatalf("targetMatches(%q) = %v, want %v", test.target, got, test.want)
			}
		})
	}
}

func TestGatewayProxiesAuthenticatedConnectUDPToWireGuardOnly(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, readErr := echo.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], addr)
		}
	}()

	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	certFile, keyFile := writeTestCertificate(t)
	serverID := uuid.New()
	secret := "masque-test-secret"
	templateText := "https://127.0.0.1:" + big.NewInt(int64(proxyPort)).String() + "/masque{?target_host,target_port}"
	gateway, err := NewGateway("127.0.0.1:"+big.NewInt(int64(proxyPort)).String(), certFile, keyFile, templateText, echo.LocalAddr().(*net.UDPAddr).Port, secret, serverID, 2)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- gateway.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = gateway.Shutdown(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := masquego.NewRequest(ctx, uritemplate.MustNew(templateText), echo.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	token := proxytoken.GenerateTunnel(proxytoken.TunnelClaims{UserID: uuid.New(), DeviceID: uuid.New(), ServerID: serverID}, secret, time.Minute)
	request.Header().Set("Authorization", "Bearer "+token)
	transport := masquego.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: true}, // test certificate
		QUICConfig:      &quic.Config{EnableDatagrams: true},
	}
	conn, _, err := transport.Dial(request)
	if err != nil {
		select {
		case serveErr := <-errCh:
			t.Fatalf("dial gateway: %v; server: %v", err, serveErr)
		default:
			t.Fatalf("dial gateway: %v", err)
		}
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte("wireguard-datagram"), nil); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "wireguard-datagram" {
		t.Fatalf("echoed datagram = %q", got)
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
