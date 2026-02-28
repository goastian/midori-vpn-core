package auth

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/repo"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ctxKey string

const UserCtxKey ctxKey = "authenticated_user"

func JWTMiddleware(cfg *config.Config, pool *pgxpool.Pool, jwks *JWKSProvider) func(http.Handler) http.Handler {
	userRepo := repo.NewUserRepo(pool)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"ok":false,"error":"missing Authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"ok":false,"error":"invalid Authorization format"}`, http.StatusUnauthorized)
				return
			}
			tokenStr := parts[1]

			keySet := jwks.KeySet()
			token, err := jwt.Parse(
				[]byte(tokenStr),
				jwt.WithKeySet(keySet),
				jwt.WithValidate(true),
				jwt.WithAcceptableSkew(30*time.Second),
			)
			if err != nil {
				log.Printf("JWT validation failed: %v", err)
				http.Error(w, `{"ok":false,"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			if token.Issuer() != cfg.AuthentikIssuer {
				http.Error(w, `{"ok":false,"error":"invalid token issuer"}`, http.StatusUnauthorized)
				return
			}

			sub := token.Subject()
			if sub == "" {
				http.Error(w, `{"ok":false,"error":"missing sub claim"}`, http.StatusUnauthorized)
				return
			}

			email := getStringClaim(token, "email")
			groups := getStringSliceClaim(token, "groups")

			user, err := userRepo.UpsertByAuthentikUID(r.Context(), sub, email, groups)
			if err != nil {
				log.Printf("JIT provisioning error for sub=%s: %v", sub, err)
				http.Error(w, `{"ok":false,"error":"user provisioning failed"}`, http.StatusInternalServerError)
				return
			}

			ctx := context.WithValue(r.Context(), UserCtxKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetUser(r *http.Request) *models.User {
	val := r.Context().Value(UserCtxKey)
	if val == nil {
		return nil
	}
	user, ok := val.(*models.User)
	if !ok {
		return nil
	}
	return user
}

func getStringClaim(token jwt.Token, key string) string {
	val, ok := token.Get(key)
	if !ok {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	return s
}

func getStringSliceClaim(token jwt.Token, key string) []string {
	val, ok := token.Get(key)
	if !ok {
		return nil
	}

	switch v := val.(type) {
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return v
	default:
		return nil
	}
}

// ValidateTokenOnly checks if a JWT is valid without extracting user info.
// Used for WebSocket authentication via query parameter.
func ValidateTokenOnly(cfg *config.Config, jwks *JWKSProvider, tokenStr string) bool {
	keySet := jwks.KeySet()
	token, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		log.Printf("WS JWT validation failed: %v", err)
		return false
	}
	if token.Issuer() != cfg.AuthentikIssuer {
		return false
	}
	return true
}
