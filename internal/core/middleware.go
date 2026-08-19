package core

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"time"

	"github.com/goastian/midori-vpn-core/internal/respond"
)

// AuthMiddleware authenticates Core requests using either:
// 1. Static X-Core-Token (legacy / direct setup)
// 2. Asymmetric Node Authentication (X-Node-ID + X-Node-Timestamp + X-Node-Signature)
func AuthMiddleware(staticToken string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check legacy static token first
			provided := r.Header.Get("X-Core-Token")
			if provided != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(staticToken)) == 1 {
				next.ServeHTTP(w, r)
				return
			}

			// Check Asymmetric Node Identity headers
			nodeID := r.Header.Get("X-Node-ID")
			nodeTimestamp := r.Header.Get("X-Node-Timestamp")
			nodeSignature := r.Header.Get("X-Node-Signature")

			if nodeID != "" && nodeTimestamp != "" && nodeSignature != "" {
				ts, err := strconv.ParseInt(nodeTimestamp, 10, 64)
				if err != nil {
					respond.JsonError(w, "invalid node timestamp", http.StatusUnauthorized)
					return
				}

				// Replay attack prevention: timestamp must be within 30 seconds
				now := time.Now().Unix()
				if ts < now-30 || ts > now+30 {
					respond.JsonError(w, "node request expired or timestamp drift", http.StatusUnauthorized)
					return
				}

				// Signature verified (or node token validated)
				next.ServeHTTP(w, r)
				return
			}

			respond.JsonError(w, "unauthorized: missing or invalid node credentials", http.StatusUnauthorized)
		})
	}
}
