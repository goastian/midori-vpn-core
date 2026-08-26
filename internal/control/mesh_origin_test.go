package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestCountryFromIPRejectsPrivateOrigins(t *testing.T) {
	h := &MeshHandler{geoClient: http.DefaultClient}
	if _, err := h.countryFromIP(context.Background(), "127.0.0.1"); err != errOriginCountryUnavailable {
		t.Fatalf("countryFromIP() error = %v, want %v", err, errOriginCountryUnavailable)
	}
	if _, err := h.countryFromIP(context.Background(), "10.0.0.4"); err != errOriginCountryUnavailable {
		t.Fatalf("countryFromIP() error = %v, want %v", err, errOriginCountryUnavailable)
	}
}

func TestCountryFromIPUsesProviderResponse(t *testing.T) {
	h := &MeshHandler{geoClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Context() == nil {
			t.Fatal("geo request has no context")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("us\n")),
			Header:     make(http.Header),
		}, nil
	})}}

	code, err := h.countryFromIP(context.Background(), "8.8.4.4")
	if err != nil {
		t.Fatalf("countryFromIP() error = %v", err)
	}
	if code != "US" {
		t.Fatalf("countryFromIP() = %q, want US", code)
	}
}

func TestWriteAutoMeshErrorReturnsStableCode(t *testing.T) {
	w := httptest.NewRecorder()
	writeAutoMeshError(w, errOriginCountryUnavailable)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.OK || body.Code != originCountryUnavailableCode || body.Error == "" {
		t.Fatalf("unexpected response: %+v", body)
	}
}
