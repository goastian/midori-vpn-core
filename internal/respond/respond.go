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
}

func JsonOK(w http.ResponseWriter, data interface{}, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{OK: true, Data: data})
}

func JsonError(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{OK: false, Error: msg})
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
