package observability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const allowedClientURI = "spiffe://midorivpn/observability/prometheus"

func TestMutualTLSRequiresAuthorizedClientURIAndTLS13(t *testing.T) {
	ca, caKey, caPEM := makeCA(t)
	directory := t.TempDir()
	serverCert, serverKey := makeCertificate(t, ca, caKey, certificateOptions{
		serial: 2, commonName: "metrics.test", dnsNames: []string{"metrics.test"},
		usage: x509.ExtKeyUsageServerAuth,
	})
	goodClientCert, goodClientKey := makeCertificate(t, ca, caKey, certificateOptions{
		serial: 3, commonName: "prometheus", uri: allowedClientURI,
		usage: x509.ExtKeyUsageClientAuth,
	})
	wrongClientCert, wrongClientKey := makeCertificate(t, ca, caKey, certificateOptions{
		serial: 4, commonName: "other-scraper", uri: "spiffe://midorivpn/observability/other",
		usage: x509.ExtKeyUsageClientAuth,
	})
	serverCertPath := writePEM(t, directory, "server.crt", "CERTIFICATE", serverCert)
	serverKeyPath := writePEM(t, directory, "server.key", "PRIVATE KEY", serverKey)
	caPath := filepath.Join(directory, "client-ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	tlsConfig, err := NewTLSConfig(serverCertPath, serverKeyPath, caPath, allowedClientURI)
	if err != nil {
		t.Fatalf("NewTLSConfig: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)

	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caPEM)
	request := func(clientCertificate *tls.Certificate, maxVersion uint16) error {
		clientTLS := &tls.Config{RootCAs: rootCAs, ServerName: "metrics.test", MinVersion: tls.VersionTLS12, MaxVersion: maxVersion}
		if clientCertificate != nil {
			clientTLS.Certificates = []tls.Certificate{*clientCertificate}
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}, Timeout: 3 * time.Second}
		response, err := client.Get(server.URL)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d", response.StatusCode)
		}
		return nil
	}

	goodClient := tlsCertificate(t, goodClientCert, goodClientKey)
	if err := request(&goodClient, tls.VersionTLS13); err != nil {
		t.Fatalf("authorized client failed: %v", err)
	}
	if err := request(nil, tls.VersionTLS13); err == nil {
		t.Fatal("client without a certificate was accepted")
	}
	wrongClient := tlsCertificate(t, wrongClientCert, wrongClientKey)
	if err := request(&wrongClient, tls.VersionTLS13); err == nil {
		t.Fatal("client with another URI identity was accepted")
	}
	if err := request(&goodClient, tls.VersionTLS12); err == nil {
		t.Fatal("TLS 1.2 client was accepted")
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	server.Config.Shutdown(shutdownContext)
}

func TestTLSConfigRejectsNonSPIFFEClientIdentity(t *testing.T) {
	ca, caKey, caPEM := makeCA(t)
	directory := t.TempDir()
	serverCert, serverKey := makeCertificate(t, ca, caKey, certificateOptions{
		serial: 5, commonName: "metrics.test", dnsNames: []string{"metrics.test"},
		usage: x509.ExtKeyUsageServerAuth,
	})
	serverCertPath := writePEM(t, directory, "server.crt", "CERTIFICATE", serverCert)
	serverKeyPath := writePEM(t, directory, "server.key", "PRIVATE KEY", serverKey)
	caPath := filepath.Join(directory, "client-ca.crt")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	for _, invalidURI := range []string{
		"https://midorivpn/observability/prometheus",
		"spiffe://midorivpn/observability/prometheus?scope=all",
		"spiffe://user@midorivpn/observability/prometheus",
	} {
		if _, err := NewTLSConfig(serverCertPath, serverKeyPath, caPath, invalidURI); err == nil {
			t.Fatalf("accepted invalid client identity %q", invalidURI)
		}
	}
}

type certificateOptions struct {
	serial     int64
	commonName string
	dnsNames   []string
	uri        string
	usage      x509.ExtKeyUsage
}

func makeCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "MidoriVPN observability test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func makeCertificate(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, options certificateOptions) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(options.serial), Subject: pkix.Name{CommonName: options.commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{options.usage}, DNSNames: options.dnsNames,
	}
	if options.uri != "" {
		parsedURI, err := url.Parse(options.uri)
		if err != nil {
			t.Fatalf("parse certificate URI: %v", err)
		}
		template.URIs = []*url.URL{parsedURI}
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal certificate key: %v", err)
	}
	return certificateDER, privateDER
}

func writePEM(t *testing.T, directory, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func tlsCertificate(t *testing.T, certificateDER, privateDER []byte) tls.Certificate {
	t.Helper()
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	certificate, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil {
		t.Fatalf("load client certificate: %v", err)
	}
	return certificate
}
