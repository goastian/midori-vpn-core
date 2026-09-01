package respond

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJsonErrorUsesCanonicalStatusCode(t *testing.T) {
	recorder := httptest.NewRecorder()
	JsonError(recorder, "wording may change", http.StatusUnauthorized)

	require.Equal(t, http.StatusUnauthorized, recorder.Code)
	require.Equal(t, "application/json", recorder.Header().Get("Content-Type"))

	var response Response
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.False(t, response.OK)
	require.Equal(t, "wording may change", response.Error)
	require.Equal(t, "unauthorized", response.Code)
}

func TestJsonErrorCodePreservesSpecificCode(t *testing.T) {
	recorder := httptest.NewRecorder()
	JsonErrorCode(recorder, "limit reached", "device_limit_reached", http.StatusConflict)

	var response Response
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.Equal(t, "device_limit_reached", response.Code)
}

func TestErrorCodeForStatus(t *testing.T) {
	tests := map[int]string{
		http.StatusBadRequest:            "bad_request",
		http.StatusUnauthorized:          "unauthorized",
		http.StatusForbidden:             "forbidden",
		http.StatusNotFound:              "not_found",
		http.StatusMethodNotAllowed:      "method_not_allowed",
		http.StatusConflict:              "conflict",
		http.StatusGone:                  "gone",
		http.StatusRequestEntityTooLarge: "request_too_large",
		http.StatusUnsupportedMediaType:  "unsupported_media_type",
		http.StatusUnprocessableEntity:   "unprocessable_entity",
		http.StatusTooManyRequests:       "rate_limited",
		http.StatusInternalServerError:   "internal_error",
		http.StatusNotImplemented:        "not_implemented",
		http.StatusBadGateway:            "bad_gateway",
		http.StatusServiceUnavailable:    "service_unavailable",
		http.StatusGatewayTimeout:        "gateway_timeout",
	}
	for status, expected := range tests {
		require.Equal(t, expected, errorCodeForStatus(status), "HTTP status %d", status)
	}
	require.Equal(t, "request_failed", errorCodeForStatus(http.StatusTeapot))
}
