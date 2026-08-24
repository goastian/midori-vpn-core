package control

import (
	"net/http"

	"github.com/goastian/midori-vpn-core/internal/respond"
)

// ExportIKEv2MobileConfig refuses to emit a plausible but unusable profile.
// IKEv2 requires an authenticated gateway plus per-user credentials, neither
// of which exists in this release yet.
func (h *Handler) ExportIKEv2MobileConfig(w http.ResponseWriter, r *http.Request) {
	respond.JsonError(w, "IKEv2 profiles are unavailable until the authenticated IKEv2 gateway is deployed", http.StatusNotImplemented)
}
