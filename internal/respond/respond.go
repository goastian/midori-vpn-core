package respond

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// appEnv holds the current environment. Set via SetAppEnv at startup.
var appEnv = "production"

// SetAppEnv configures the application environment for error responses.
func SetAppEnv(env string) {
	appEnv = env
}

type Response struct {
	OK    bool        `json:"ok"`
	Data  interface{} `json:"data,omitempty"`
	Error string      `json:"error,omitempty"`
	Code  string      `json:"code,omitempty"`
}

func JsonOK(w http.ResponseWriter, data interface{}, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{OK: true, Data: data})
}

func JsonError(w http.ResponseWriter, msg string, code int) {
	JsonErrorCode(w, msg, errorCodeForStatus(code), code)
}

// JsonErrorCode returns a stable machine-readable code alongside the public
// error message. Clients should branch on Code instead of matching prose.
func JsonErrorCode(w http.ResponseWriter, msg, errorCode string, status int) {
	if errorCode == "" {
		errorCode = errorCodeForStatus(status)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{OK: false, Error: msg, Code: errorCode})
}

func errorCodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusConflict:
		return "conflict"
	case http.StatusGone:
		return "gone"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	case http.StatusUnprocessableEntity:
		return "unprocessable_entity"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusNotImplemented:
		return "not_implemented"
	case http.StatusBadGateway:
		return "bad_gateway"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	case http.StatusGatewayTimeout:
		return "gateway_timeout"
	case http.StatusInternalServerError:
		return "internal_error"
	default:
		return "request_failed"
	}
}

// SafeError returns a generic error message in production and the real
// error in development. It always logs the real error for debugging.
func SafeError(w http.ResponseWriter, publicMsg string, err error, code int) {
	slog.Error(publicMsg, "error", err)
	if appEnv == "development" {
		JsonError(w, err.Error(), code)
		return
	}
	JsonError(w, publicMsg, code)
}
