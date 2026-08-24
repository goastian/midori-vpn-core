package core

import (
	"net/http"

	"github.com/goastian/midori-vpn-core/internal/nodeauth"
)

func AuthMiddleware(verifier *nodeauth.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return verifier.Middleware(next)
	}
}
