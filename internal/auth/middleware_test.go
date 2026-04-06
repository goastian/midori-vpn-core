package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
)

// testJWKS creates a JWKSProvider backed by an in-memory RSA key pair.
func testJWKS(t *testing.T, privKey *rsa.PrivateKey) *auth.JWKSProvider {
	t.Helper()

	pubKeyJWK, err := jwk.FromRaw(privKey.Public())
	if err != nil {
		t.Fatalf("jwk.FromRaw: %v", err)
	}
	_ = pubKeyJWK.Set(jwk.AlgorithmKey, jwa.RS256)
	_ = pubKeyJWK.Set(jwk.KeyIDKey, "test-key-1")

	set := jwk.NewSet()
	_ = set.AddKey(pubKeyJWK)

	// Serve JWKS over a local HTTP server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		w.Write(buf)
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{
		AuthentikJWKSURL: srv.URL,
		AuthentikIssuer:  "https://auth.test.local",
		ConfigDir:        t.TempDir(),
	}

	provider, err := auth.NewJWKSProvider(cfg)
	if err != nil {
		t.Fatalf("NewJWKSProvider: %v", err)
	}
	return provider
}

func signToken(t *testing.T, privKey *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	builder := jwt.New()
	for k, v := range claims {
		_ = builder.Set(k, v)
	}

	privJWK, err := jwk.FromRaw(privKey)
	if err != nil {
		t.Fatalf("jwk.FromRaw priv: %v", err)
	}
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.RS256)
	_ = privJWK.Set(jwk.KeyIDKey, "test-key-1")

	signed, err := jwt.Sign(builder, jwt.WithKey(jwa.RS256, privJWK))
	if err != nil {
		t.Fatalf("jwt.Sign: %v", err)
	}
	return string(signed)
}

func TestValidateTokenOnly_ValidToken(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	token := signToken(t, privKey, map[string]interface{}{
		"iss": "https://auth.test.local",
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	if !auth.ValidateTokenOnly(cfg, jwks, token) {
		t.Error("expected valid token to pass validation")
	}
}

func TestValidateTokenOnly_WrongIssuer(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	token := signToken(t, privKey, map[string]interface{}{
		"iss": "https://evil.example.com",
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	if auth.ValidateTokenOnly(cfg, jwks, token) {
		t.Error("expected token with wrong issuer to fail")
	}
}

func TestValidateTokenOnly_ExpiredToken(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	token := signToken(t, privKey, map[string]interface{}{
		"iss": "https://auth.test.local",
		"sub": "user-123",
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	if auth.ValidateTokenOnly(cfg, jwks, token) {
		t.Error("expected expired token to fail")
	}
}

func TestValidateTokenOnly_InvalidSignature(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	// Sign with a different key
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token := signToken(t, otherKey, map[string]interface{}{
		"iss": "https://auth.test.local",
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	if auth.ValidateTokenOnly(cfg, jwks, token) {
		t.Error("expected token with invalid signature to fail")
	}
}

func TestValidateTokenAndExtractClaims_Valid(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	token := signToken(t, privKey, map[string]interface{}{
		"iss":    "https://auth.test.local",
		"sub":    "user-456",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"groups": []string{"plan-pro", "vpn-admins"},
	})

	claims, err := auth.ValidateTokenAndExtractClaims(cfg, jwks, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Subject != "user-456" {
		t.Errorf("expected subject 'user-456', got %q", claims.Subject)
	}
	if len(claims.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(claims.Groups))
	}
}

func TestValidateTokenAndExtractClaims_MissingSub(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	token := signToken(t, privKey, map[string]interface{}{
		"iss": "https://auth.test.local",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	_, err = auth.ValidateTokenAndExtractClaims(cfg, jwks, token)
	if err == nil {
		t.Error("expected error for missing sub claim")
	}
}

func TestValidateTokenAndExtractClaims_WrongIssuer(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	token := signToken(t, privKey, map[string]interface{}{
		"iss": "https://wrong.issuer.com",
		"sub": "user-789",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	_, err = auth.ValidateTokenAndExtractClaims(cfg, jwks, token)
	if err == nil {
		t.Error("expected error for wrong issuer")
	}
}

func TestGetUser_NoUserInContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	user := auth.GetUser(req)
	if user != nil {
		t.Error("expected nil user when no user in context")
	}
}

func TestJWTMiddleware_MissingAuthHeader(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	handler := auth.JWTMiddleware(cfg, nil, jwks)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestJWTMiddleware_InvalidAuthFormat(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	handler := auth.JWTMiddleware(cfg, nil, jwks)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestJWTMiddleware_InvalidToken(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := testJWKS(t, privKey)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local"}

	handler := auth.JWTMiddleware(cfg, nil, jwks)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.value")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
