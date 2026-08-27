package clientpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuthorityIssuesVerifiedClientCertificateFromCSR(t *testing.T) {
	authority, caCertificate := testAuthority(t)
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "attacker-controlled-subject"},
	}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	issued, err := authority.Issue(string(csrPEM), id, now)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Subject.CommonName != "device:"+id.String() {
		t.Fatalf("subject CN = %q", certificate.Subject.CommonName)
	}
	if certificate.IsCA || len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("unexpected certificate constraints: %+v", certificate)
	}
	if len(certificate.URIs) != 1 || certificate.URIs[0].String() != "urn:midorivpn:device:"+id.String() {
		t.Fatalf("unexpected device identity: %v", certificate.URIs)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify issued certificate: %v", err)
	}
	if issued.PublicKeySHA256 == "" || issued.SerialNumber == "" {
		t.Fatalf("missing public metadata: %+v", issued)
	}
}

func TestAuthorityRejectsIncompatibleCSRKey(t *testing.T) {
	authority, _ := testAuthority(t)
	weakKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, weakKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if _, err := authority.Issue(string(csrPEM), uuid.New(), time.Now()); err == nil {
		t.Fatal("Issue() accepted a 2048-bit RSA CSR")
	}
}

func TestAuthorityCreatesSignedCRL(t *testing.T) {
	authority, caCertificate := testAuthority(t)
	now := time.Now().UTC().Truncate(time.Second)
	crlDER, err := authority.CreateCRL([]RevokedCertificate{{
		SerialNumber: "2a", RevokedAt: now.Add(-time.Hour), Reason: "key_compromise",
	}}, now)
	if err != nil {
		t.Fatalf("CreateCRL() error = %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(caCertificate); err != nil {
		t.Fatalf("verify CRL signature: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("unexpected CRL entries: %+v", crl.RevokedCertificateEntries)
	}
}

func testAuthority(t *testing.T) (*Authority, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MidoriVPN Test Client CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certificatePath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	authority, err := LoadAuthority(certificatePath, keyPath, 90*24*time.Hour, "https://vpn.example/crl.pem")
	if err != nil {
		t.Fatal(err)
	}
	return authority, certificate
}
