package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/db"
)

func TestJWTMiddlewareAudienceBeforeProvisioning(t *testing.T) {
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
		for _, accepted := range []bool{false, true} {
			name := kind + "/rejected"
			if accepted {
				name = kind + "/accepted"
			}
			t.Run(name, func(t *testing.T) {
				subject := uuid.NewString()
				t.Cleanup(func() {
					_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE authentik_uid = $1", subject)
				})
				audience := "other-client"
				if accepted {
					audience = "vpn-client"
				}
				claims := map[string]any{
					"active": true, "iss": "https://auth.test.local", "sub": subject,
					"aud": []string{audience}, "email": subject + "@test.invalid",
					"exp":    time.Now().Add(time.Hour).Unix(),
					"groups": []string{"vpn-users"},
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if kind == "jwt" {
						t.Error("a signed token with an invalid audience must not fall back to introspection")
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
				handler := auth.JWTMiddleware(cfg, pool, jwks)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if user := auth.GetUser(r); user == nil || user.AuthentikUID != subject {
						t.Error("authenticated identity is missing or incorrect")
					}
					w.WriteHeader(http.StatusOK)
				}))
				request := httptest.NewRequest(http.MethodGet, "/test", nil)
				request.Header.Set("Authorization", "Bearer "+token)
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				want := http.StatusUnauthorized
				if accepted {
					want = http.StatusOK
				}
				if recorder.Code != want {
					t.Fatalf("status = %d, want %d", recorder.Code, want)
				}
				var users int
				if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM users WHERE authentik_uid = $1", subject).Scan(&users); err != nil {
					t.Fatal(err)
				}
				if (users == 1) != accepted {
					t.Fatalf("provisioned users = %d, accepted=%v", users, accepted)
				}
			})
		}
	}
}
