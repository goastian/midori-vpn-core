package nodeplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/goastian/midori-vpn-core/internal/desiredstate"
	"github.com/goastian/midori-vpn-core/internal/fleetauth"
	"github.com/goastian/midori-vpn-core/internal/httpx"
)

type Client struct {
	baseURL  string
	client   *http.Client
	identity *fleetauth.Identity
}

func NewClient(baseURL string, identity *fleetauth.Identity, client *http.Client, allowHTTP bool) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("control plane URL must be an absolute URL without credentials, query or fragment")
	}
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return nil, errors.New("control plane URL must use HTTPS")
	}
	if parsed.Path != "" {
		return nil, errors.New("control plane URL must not contain a path")
	}
	if identity == nil {
		return nil, errors.New("core node identity is required")
	}
	if client == nil {
		client = httpx.NewClient(15 * time.Second)
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), client: client, identity: identity}, nil
}

func (c *Client) EnrollFromTokenFile(ctx context.Context, tokenPath string) error {
	token, err := fleetauth.ReadEnrollmentToken(tokenPath)
	if err != nil {
		return fmt.Errorf("load node enrollment token: %w", err)
	}
	request := EnrollmentRequest{
		NodeID:    c.identity.NodeID().String(),
		PublicKey: c.identity.EncodedPublicKey(),
	}
	if err := c.send(ctx, EnrollmentPath, request, token); err != nil {
		return err
	}
	if err := fleetauth.DestroyEnrollmentToken(tokenPath, token); err != nil {
		return fmt.Errorf("destroy consumed node enrollment token: %w", err)
	}
	return nil
}

func (c *Client) Heartbeat(ctx context.Context, heartbeat HeartbeatRequest) error {
	return c.send(ctx, HeartbeatPath, heartbeat, "")
}

func (c *Client) FetchDesiredState(ctx context.Context) (*desiredstate.SignedBundle, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+DesiredStatePath, nil)
	if err != nil {
		return nil, false, fmt.Errorf("create desired state request: %w", err)
	}
	if err := c.identity.Sign(req, nil); err != nil {
		return nil, false, fmt.Errorf("sign desired state request: %w", err)
	}
	response, err := c.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetch desired state: %w", err)
	}
	defer response.Body.Close()
	responseBody, readErr := httpx.ReadBody(response.Body, 256<<10)
	if readErr != nil {
		return nil, false, fmt.Errorf("read desired state response: %w", readErr)
	}
	if response.StatusCode == http.StatusNoContent {
		return nil, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, false, &ResponseError{Status: response.StatusCode, Bytes: len(responseBody)}
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	var envelope struct {
		OK   bool                      `json:"ok"`
		Data desiredstate.SignedBundle `json:"data"`
	}
	if err := decoder.Decode(&envelope); err != nil || !envelope.OK {
		return nil, false, errors.New("control plane returned an invalid desired state response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, false, errors.New("control plane returned trailing desired state data")
	}
	return &envelope.Data, true, nil
}

func (c *Client) send(ctx context.Context, path string, payload any, bearerToken string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode node-plane request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create node-plane request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	if err := c.identity.Sign(req, body); err != nil {
		return fmt.Errorf("sign node-plane request: %w", err)
	}
	response, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("send node-plane request: %w", err)
	}
	defer response.Body.Close()
	responseBody, readErr := httpx.ReadBody(response.Body, 64<<10)
	if readErr != nil {
		return fmt.Errorf("read node-plane response: %w", readErr)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &ResponseError{Status: response.StatusCode, Bytes: len(responseBody)}
	}
	return nil
}

type ResponseError struct {
	Status int
	Bytes  int
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("control plane rejected node request with status %d (%d response bytes)", e.Status, e.Bytes)
}

func EnrollmentTokenExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
