package control

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/respond"
)

func (h *Handler) AdminListTrustedExtensionOrigins(w http.ResponseWriter, r *http.Request) {
	origins, err := h.trustedExtensionRepo.List(r.Context())
	if err != nil {
		respond.JsonError(w, "failed to list trusted extension origins", http.StatusInternalServerError)
		return
	}
	respond.JsonOK(w, origins, http.StatusOK)
}

func (h *Handler) AdminUpdateTrustedExtensionOrigin(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respond.JsonError(w, "invalid trusted extension origin id", http.StatusBadRequest)
		return
	}
	var request struct {
		Revoked *bool `json:"revoked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Revoked == nil {
		respond.JsonError(w, "revoked is required", http.StatusBadRequest)
		return
	}
	origin, err := h.trustedExtensionRepo.SetRevokedByID(r.Context(), id, *request.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		respond.JsonError(w, "trusted extension origin not found", http.StatusNotFound)
		return
	}
	if err != nil {
		respond.JsonError(w, "failed to update trusted extension origin", http.StatusInternalServerError)
		return
	}
	action := "admin.extension-origin.restore"
	if *request.Revoked {
		action = "admin.extension-origin.revoke"
	}
	admin := auth.GetUser(r)
	_ = h.auditRepo.Log(r.Context(), &admin.ID, action, map[string]interface{}{
		"origin_id": id,
		"origin":    origin,
	}, r.RemoteAddr)
	respond.JsonOK(w, map[string]interface{}{
		"id":      id,
		"origin":  origin,
		"revoked": *request.Revoked,
	}, http.StatusOK)
}
