// Package observability provides the dedicated mutual-TLS server used for
// private Prometheus scraping and regional target discovery.
package observability

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/goastian/midori-vpn-core/internal/httpx"
)

func NewServer(addr, certificatePath, keyPath, clientCAPath, allowedClientURI string, handler http.Handler) (*http.Server, error) {
	if handler == nil {
		return nil, errors.New("observability handler is required")
	}
	tlsConfig, err := NewTLSConfig(certificatePath, keyPath, clientCAPath, allowedClientURI)
	if err != nil {
		return nil, err
	}
	server := httpx.NewAPIServer(addr, handler)
	server.TLSConfig = tlsConfig
	return server, nil
}

func NewTLSConfig(certificatePath, keyPath, clientCAPath, allowedClientURI string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load observability server identity: %w", err)
	}
	clientCAPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read observability client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return nil, errors.New("observability client CA contains no certificates")
	}
	wantURI, err := url.Parse(allowedClientURI)
	if err != nil || wantURI.Scheme != "spiffe" || wantURI.Host == "" || wantURI.Path == "" ||
		wantURI.User != nil || wantURI.RawQuery != "" || wantURI.Fragment != "" {
		return nil, errors.New("observability client URI is invalid")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
				return errors.New("observability client certificate was not verified")
			}
			for _, presentedURI := range state.PeerCertificates[0].URIs {
				if presentedURI.String() == wantURI.String() {
					return nil
				}
			}
			return errors.New("observability client identity is not authorized")
		},
	}, nil
}
