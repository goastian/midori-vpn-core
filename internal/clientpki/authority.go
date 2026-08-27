// Package clientpki signs short-lived client certificates from device-created
// CSRs. It never accepts or stores client private key material.
package clientpki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxCSRPEMBytes = 16 << 10

type Authority struct {
	certificate    *x509.Certificate
	signer         crypto.Signer
	certificatePEM string
	certificateTTL time.Duration
	crlURL         string
}

type IssuedCertificate struct {
	SerialNumber    string
	CertificatePEM  string
	PublicKeySHA256 string
	NotBefore       time.Time
	NotAfter        time.Time
}

type RevokedCertificate struct {
	SerialNumber string
	RevokedAt    time.Time
	Reason       string
}

func LoadAuthority(certificatePath, keyPath string, certificateTTL time.Duration, crlURL string) (*Authority, error) {
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("read client CA certificate: %w", err)
	}
	block, remainder := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, errors.New("client CA certificate must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse client CA certificate: %w", err)
	}
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, errors.New("client CA certificate must allow certificate and CRL signing")
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, errors.New("client CA certificate is not currently valid")
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA private key: %w", err)
	}
	signer, err := parseSigner(keyPEM)
	if err != nil {
		return nil, err
	}
	caPublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal client CA public key: %w", err)
	}
	signerPublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal client CA signer public key: %w", err)
	}
	if !bytes.Equal(caPublicKey, signerPublicKey) {
		return nil, errors.New("client CA certificate and private key do not match")
	}
	if certificateTTL < 24*time.Hour || certificateTTL > 365*24*time.Hour {
		return nil, errors.New("client certificate TTL must be between 24 hours and 365 days")
	}
	if crlURL != "" {
		parsed, err := url.Parse(crlURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return nil, errors.New("client CRL URL must be an absolute HTTPS URL")
		}
	}
	return &Authority{
		certificate:    certificate,
		signer:         signer,
		certificatePEM: string(certificatePEM),
		certificateTTL: certificateTTL,
		crlURL:         crlURL,
	}, nil
}

func parseSigner(keyPEM []byte) (crypto.Signer, error) {
	block, remainder := pem.Decode(keyPEM)
	if block == nil || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, errors.New("client CA key must contain exactly one unencrypted PEM private key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported client CA private key type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse client CA private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("client CA private key does not implement crypto.Signer")
	}
	return signer, nil
}

func (a *Authority) CACertificatePEM() string {
	return a.certificatePEM
}

func (a *Authority) Issue(csrPEM string, certificateID uuid.UUID, now time.Time) (*IssuedCertificate, error) {
	if len(csrPEM) == 0 || len(csrPEM) > maxCSRPEMBytes {
		return nil, errors.New("CSR must be a non-empty PEM document no larger than 16 KiB")
	}
	block, remainder := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, errors.New("CSR must contain exactly one PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify CSR signature: %w", err)
	}
	if err := validateClientPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CSR public key: %w", err)
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	// ASN.1 UTCTime/GeneralizedTime in an X.509 certificate has second
	// precision. Return the same precision in the API metadata so clients can
	// compare the signed certificate with the enrollment response exactly.
	certificateTime := now.UTC().Truncate(time.Second)
	notBefore := certificateTime.Add(-5 * time.Minute)
	notAfter := certificateTime.Add(a.certificateTTL)
	if notAfter.After(a.certificate.NotAfter) {
		notAfter = a.certificate.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, errors.New("client CA expires too soon to issue a certificate")
	}
	identity, err := url.Parse("urn:midorivpn:device:" + certificateID.String())
	if err != nil {
		return nil, fmt.Errorf("build certificate identity: %w", err)
	}
	subjectKeyID := sha256.Sum256(publicKeyDER)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MidoriVPN"},
			CommonName:   "device:" + certificateID.String(),
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{identity},
		SubjectKeyId:          subjectKeyID[:],
		AuthorityKeyId:        a.certificate.SubjectKeyId,
	}
	if a.crlURL != "" {
		template.CRLDistributionPoints = []string{a.crlURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, csr.PublicKey, a.signer)
	if err != nil {
		return nil, fmt.Errorf("sign client certificate: %w", err)
	}
	return &IssuedCertificate{
		SerialNumber:    strings.ToLower(serialNumber.Text(16)),
		CertificatePEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PublicKeySHA256: hex.EncodeToString(fingerprint[:]),
		NotBefore:       notBefore,
		NotAfter:        notAfter,
	}, nil
}

func validateClientPublicKey(publicKey any) error {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if key.Curve.Params().Name != "P-256" && key.Curve.Params().Name != "P-384" {
			return errors.New("CSR ECDSA key must use P-256 or P-384")
		}
	case *rsa.PublicKey:
		if key.N.BitLen() < 3072 {
			return errors.New("CSR RSA key must be at least 3072 bits")
		}
	case ed25519.PublicKey:
		return errors.New("CSR Ed25519 keys are not accepted by the cross-protocol compatibility profile")
	default:
		return fmt.Errorf("unsupported CSR public key type %T", publicKey)
	}
	return nil
}

func randomSerialNumber() (*big.Int, error) {
	serialBytes := make([]byte, 20)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func (a *Authority) CreateCRL(entries []RevokedCertificate, now time.Time) ([]byte, error) {
	revoked := make([]x509.RevocationListEntry, 0, len(entries))
	for _, entry := range entries {
		serial := new(big.Int)
		if _, ok := serial.SetString(entry.SerialNumber, 16); !ok || serial.Sign() <= 0 {
			return nil, fmt.Errorf("invalid revoked certificate serial %q", entry.SerialNumber)
		}
		revoked = append(revoked, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: entry.RevokedAt.UTC(),
			ReasonCode:     revocationReasonCode(entry.Reason),
		})
	}
	template := &x509.RevocationList{
		Number:                    big.NewInt(now.UTC().Unix()),
		ThisUpdate:                now.UTC().Add(-time.Minute),
		NextUpdate:                now.UTC().Add(24 * time.Hour),
		RevokedCertificateEntries: revoked,
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, a.certificate, a.signer)
	if err != nil {
		return nil, fmt.Errorf("sign client certificate revocation list: %w", err)
	}
	return der, nil
}

func revocationReasonCode(reason string) int {
	switch reason {
	case "key_compromise":
		return 1
	case "superseded":
		return 4
	case "cessation_of_operation":
		return 5
	default:
		return 0
	}
}
