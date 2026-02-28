package api

import (
	"encoding/json"
	"net/http"
)

type Response struct {
	OK      bool        `json:"ok"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func jsonOK(w http.ResponseWriter, data interface{}, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{OK: true, Data: data})
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{OK: false, Error: msg})
}
