package auth

import (
	"context"
	"fmt"
	"log/slog"
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

func sameIssuer(actual, expected string) bool {
	return strings.TrimRight(actual, "/") == strings.TrimRight(expected, "/")
}

// isJWE returns true when the token has 5 dot-separated segments, which is
// the compact serialization of a JWE (encrypted token). JWE tokens cannot be
// validated with a public JWKS; they must go through introspection.
func isJWE(tokenStr string) bool {
	return strings.Count(tokenStr, ".") == 4
}

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
			tokenKind := "jwt"
			if isJWE(tokenStr) {
				tokenKind = "jwe"
			}
			slog.Debug("auth middleware token received",
				"path", r.URL.Path,
				"method", r.Method,
				"remote", r.RemoteAddr,
				"token_kind", tokenKind,
			)

			var sub string
			var email string
			var groups []string

			if isJWE(tokenStr) {
				// JWE tokens (5 segments) are encrypted and cannot be validated
				// locally with JWKS public keys — send directly to introspection.
				slog.Debug("JWE token detected, using introspection")
				claims, intErr := introspectToken(cfg, tokenStr)
				if intErr != nil {
					slog.Warn("JWE token introspection failed",
						"path", r.URL.Path,
						"method", r.Method,
						"remote", r.RemoteAddr,
						"error", intErr,
					)
					http.Error(w, `{"ok":false,"error":"invalid token"}`, http.StatusUnauthorized)
					return
				}
				if claims.Iss != "" && !sameIssuer(claims.Iss, cfg.AuthentikTokenIssuer()) {
					slog.Warn("JWE introspection issuer mismatch",
						"got", claims.Iss,
						"expected", cfg.AuthentikTokenIssuer(),
					)
					http.Error(w, `{"ok":false,"error":"invalid token issuer"}`, http.StatusUnauthorized)
					return
				}
				sub = claims.Sub
				email = claims.Email
				groups = introspectionGroups(claims.Groups)
			} else {
				keySet := jwks.KeySet()
				token, err := jwt.Parse(
					[]byte(tokenStr),
					jwt.WithKeySet(keySet),
					jwt.WithValidate(true),
					jwt.WithAcceptableSkew(30*time.Second),
				)

				if err != nil {
					slog.Warn("JWT validation failed, trying introspection fallback",
						"path", r.URL.Path,
						"method", r.Method,
						"remote", r.RemoteAddr,
						"error", err,
					)
					claims, intErr := introspectToken(cfg, tokenStr)
					if intErr != nil {
						slog.Warn("Token introspection failed",
							"path", r.URL.Path,
							"method", r.Method,
							"remote", r.RemoteAddr,
							"error", intErr,
						)
						http.Error(w, `{"ok":false,"error":"invalid token"}`, http.StatusUnauthorized)
						return
					}
					if claims.Iss != "" && !sameIssuer(claims.Iss, cfg.AuthentikTokenIssuer()) {
						http.Error(w, `{"ok":false,"error":"invalid token issuer"}`, http.StatusUnauthorized)
						return
					}
					sub = claims.Sub
					email = claims.Email
					groups = introspectionGroups(claims.Groups)
				} else {
					if !sameIssuer(token.Issuer(), cfg.AuthentikTokenIssuer()) {
						http.Error(w, `{"ok":false,"error":"invalid token issuer"}`, http.StatusUnauthorized)
						return
					}
					sub = token.Subject()
					email = getStringClaim(token, "email")
					groups = getStringSliceClaim(token, "groups")
				}
			}

			if sub == "" {
				http.Error(w, `{"ok":false,"error":"missing sub claim"}`, http.StatusUnauthorized)
				return
			}

			user, err := userRepo.UpsertByAuthentikUID(r.Context(), sub, email, groups)
			if err != nil {
				slog.Error("JIT provisioning error", "sub", sub, "error", err)
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
	if isJWE(tokenStr) {
		claims, intErr := introspectToken(cfg, tokenStr)
		if intErr != nil {
			slog.Warn("WS JWE introspection failed", "introspection_error", intErr)
			return false
		}
		if claims.Iss != "" && !sameIssuer(claims.Iss, cfg.AuthentikTokenIssuer()) {
			return false
		}
		return claims.Sub != ""
	}

	keySet := jwks.KeySet()
	token, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		claims, intErr := introspectToken(cfg, tokenStr)
		if intErr != nil {
			slog.Warn("WS JWT validation/introspection failed", "jwt_error", err, "introspection_error", intErr)
			return false
		}
		if claims.Iss != "" && !sameIssuer(claims.Iss, cfg.AuthentikTokenIssuer()) {
			return false
		}
		return claims.Sub != ""
	}
	if !sameIssuer(token.Issuer(), cfg.AuthentikTokenIssuer()) {
		return false
	}
	return true
}

// WSClaims holds the subset of JWT claims needed for WebSocket authorization.
type WSClaims struct {
	Subject string
	Groups  []string
}

// ValidateTokenAndExtractClaims validates a JWT and returns the subject and groups.
func ValidateTokenAndExtractClaims(cfg *config.Config, jwks *JWKSProvider, tokenStr string) (*WSClaims, error) {
	if isJWE(tokenStr) {
		claims, intErr := introspectToken(cfg, tokenStr)
		if intErr != nil {
			return nil, fmt.Errorf("jwe introspection failed: %w", intErr)
		}
		if claims.Iss != "" && !sameIssuer(claims.Iss, cfg.AuthentikTokenIssuer()) {
			return nil, fmt.Errorf("invalid issuer: %s", claims.Iss)
		}
		if claims.Sub == "" {
			return nil, fmt.Errorf("missing sub claim")
		}
		return &WSClaims{
			Subject: claims.Sub,
			Groups:  introspectionGroups(claims.Groups),
		}, nil
	}

	keySet := jwks.KeySet()
	token, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		claims, intErr := introspectToken(cfg, tokenStr)
		if intErr != nil {
			return nil, fmt.Errorf("jwt parse failed: %w; introspection failed: %v", err, intErr)
		}
		if claims.Iss != "" && !sameIssuer(claims.Iss, cfg.AuthentikTokenIssuer()) {
			return nil, fmt.Errorf("invalid issuer: %s", claims.Iss)
		}
		if claims.Sub == "" {
			return nil, fmt.Errorf("missing sub claim")
		}
		return &WSClaims{
			Subject: claims.Sub,
			Groups:  introspectionGroups(claims.Groups),
		}, nil
	}
	if !sameIssuer(token.Issuer(), cfg.AuthentikTokenIssuer()) {
		return nil, fmt.Errorf("invalid issuer: %s", token.Issuer())
	}
	sub := token.Subject()
	if sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	return &WSClaims{
		Subject: sub,
		Groups:  getStringSliceClaim(token, "groups"),
	}, nil
}
