package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/db"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

var admissionCases = []struct {
	name     string
	groups   []string
	allowed  bool
	existing bool
}{
	{"missing groups", nil, false, false},
	{"empty groups", []string{}, false, false},
	{"plan only", []string{"plan-pro"}, false, false},
	{"vpn admin only", []string{"vpn-admins"}, false, false},
	{"global admins", []string{"admins", "authentik Admins"}, false, false},
	{"similar group", []string{"vpn-users-extra"}, false, false},
	{"different case", []string{"VPN-USERS"}, false, false},
	{"vpn user", []string{"vpn-users"}, true, false},
	{"vpn operator", []string{"vpn-users", "vpn-admins"}, true, false},
	{"membership removed", []string{"plan-pro"}, false, true},
}

func admissionClaims(subject string, groups []string) map[string]any {
	claims := map[string]any{
		"active": true, "iss": "https://auth.test.local", "sub": subject,
		"aud": []string{"vpn-client"}, "email": subject + "@test.invalid",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if groups != nil {
		claims["groups"] = groups
	}
	return claims
}

func TestJWTMiddlewareGroupAdmissionBeforeProvisioning(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}
	if err := db.RunMigrations(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := testJWKS(t, key)

	for _, kind := range []string{"jwt", "opaque", "jwe"} {
		for _, test := range admissionCases {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				subject := uuid.NewString()
				t.Cleanup(func() {
					if _, err := pool.Exec(context.Background(), "DELETE FROM users WHERE authentik_uid = $1", subject); err != nil {
						t.Errorf("cleanup user: %v", err)
					}
				})
				oldGroups := []string{"vpn-users", "vpn-admins"}
				oldEmail := "unchanged@test.invalid"
				if test.existing {
					if _, err := repo.NewUserRepo(pool).UpsertByAuthentikUID(context.Background(), subject, oldEmail, oldGroups); err != nil {
						t.Fatal(err)
					}
				}
				claims := admissionClaims(subject, test.groups)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if kind == "jwt" {
						t.Error("signed token admission must not fall back to introspection")
					}
					_ = json.NewEncoder(w).Encode(claims)
				}))
				defer server.Close()
				cfg := &config.Config{
					AuthentikIssuer: "https://auth.test.local", AuthentikClientID: "vpn-client",
					AuthentikClientSecret: "test-secret", AuthentikIntrospectionURLOverride: server.URL,
				}
				token := subject
				if kind == "jwt" {
					token = signToken(t, key, claims)
				} else if kind == "jwe" {
					token += ".a.b.c.d"
				}
				defer auth.InvalidateIntrospection(token)
				called := false
				handler := auth.JWTMiddleware(cfg, pool, jwks)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					user := auth.GetUser(r)
					if user == nil || user.AuthentikUID != subject || !slices.Equal(user.Groups, test.groups) {
						t.Error("admitted identity or groups are incorrect")
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				request := httptest.NewRequest(http.MethodGet, "/test", nil)
				request.Header.Set("Authorization", "Bearer "+token)
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				want := http.StatusForbidden
				if test.allowed {
					want = http.StatusNoContent
				}
				if recorder.Code != want || called != test.allowed {
					t.Fatalf("status = %d, called = %v; want %d, %v", recorder.Code, called, want, test.allowed)
				}
				var count int
				if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM users WHERE authentik_uid = $1", subject).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if (count == 1) != (test.allowed || test.existing) {
					t.Fatalf("unexpected provisioned user count: %d", count)
				}
				if test.existing {
					var email string
					var groups []string
					if err := pool.QueryRow(context.Background(), "SELECT email, groups FROM users WHERE authentik_uid = $1", subject).Scan(&email, &groups); err != nil {
						t.Fatal(err)
					}
					if email != oldEmail || !slices.Equal(groups, oldGroups) {
						t.Fatal("denied token changed the existing user")
					}
				}
			})
		}
	}
}

func TestTokenValidationRequiresVPNUserGroup(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := testJWKS(t, key)
	for _, kind := range []string{"jwt", "opaque", "jwe"} {
		for _, test := range admissionCases {
			t.Run(kind+"/"+test.name, func(t *testing.T) {
				subject := uuid.NewString()
				claims := admissionClaims(subject, test.groups)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if kind == "jwt" {
						t.Error("signed token admission must not fall back to introspection")
					}
					_ = json.NewEncoder(w).Encode(claims)
				}))
				defer server.Close()
				cfg := &config.Config{
					AuthentikIssuer: "https://auth.test.local", AuthentikClientID: "vpn-client",
					AuthentikClientSecret: "test-secret", AuthentikIntrospectionURLOverride: server.URL,
				}
				token := subject
				if kind == "jwt" {
					token = signToken(t, key, claims)
				} else if kind == "jwe" {
					token += ".a.b.c.d"
				}
				defer auth.InvalidateIntrospection(token)
				if got := auth.ValidateTokenOnly(cfg, jwks, token); got != test.allowed {
					t.Errorf("ValidateTokenOnly = %v, want %v", got, test.allowed)
				}
				identity, err := auth.ValidateTokenAndExtractClaims(cfg, jwks, token)
				if (err == nil) != test.allowed {
					t.Fatalf("identity = %#v, error = %v; want allowed = %v", identity, err, test.allowed)
				}
				if test.allowed && (identity.Subject != subject || !slices.Equal(identity.Groups, test.groups)) {
					t.Fatal("validated identity or groups changed")
				}
			})
		}
	}
}

func TestTokenValidationRejectsMissingSubject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := testJWKS(t, key)
	cfg := &config.Config{AuthentikIssuer: "https://auth.test.local", AuthentikClientID: "vpn-client"}
	token := signToken(t, key, admissionClaims("", []string{"vpn-users"}))
	if auth.ValidateTokenOnly(cfg, jwks, token) {
		t.Error("token without a subject was accepted")
	}
	if _, err := auth.ValidateTokenAndExtractClaims(cfg, jwks, token); err == nil {
		t.Error("claims without a subject were accepted")
	}
}
