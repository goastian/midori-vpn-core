package api

import (
	"crypto/subtle"
	"net/http"
)

func AuthMiddleware(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provided := r.Header.Get("X-Core-Token")
			if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
				jsonError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
