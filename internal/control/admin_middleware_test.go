package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/models"
)

func TestAdminOnlyRejectsMissingAndNonAdminUsers(t *testing.T) {
	handler := AdminOnly(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was called")
	}))

	for name, user := range map[string]*models.User{
		"missing":   nil,
		"non-admin": {Groups: []string{"vpn-users"}},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/health", nil)
			if user != nil {
				request = request.WithContext(context.WithValue(context.Background(), auth.UserCtxKey, user))
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
			}
		})
	}
}

func TestAdminOnlyAllowsAdminUser(t *testing.T) {
	called := false
	handler := AdminOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/health", nil)
	request = request.WithContext(context.WithValue(context.Background(), auth.UserCtxKey, &models.User{Groups: []string{"vpn-admins"}}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("called = %t, status = %d", called, recorder.Code)
	}
}
