package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/goastian/midori-vpn-core/internal/models"
)

var coreHTTP = &http.Client{Timeout: 10 * time.Second}

type CoreAddPeerResponse struct {
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
	Endpoint  string `json:"endpoint"`
}

type coreAPIResponse struct {
	OK   bool            `json:"ok"`
	Data json.RawMessage `json:"data"`
	Err  string          `json:"error"`
}

func callCoreAddPeer(server *models.VPNServer, pubkey string) (*CoreAddPeerResponse, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"public_key": pubkey,
		"keepalive":  25,
	})

	coreURL := fmt.Sprintf("http://%s:%d/api/v1/peers", server.Host, server.Port)
	req, err := http.NewRequest(http.MethodPost, coreURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Core-Token", server.CoreToken)

	resp, err := coreHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("core unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var apiResp coreAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid core response: %s", string(body))
	}

	if !apiResp.OK {
		return nil, fmt.Errorf("core error: %s", apiResp.Err)
	}

	var result CoreAddPeerResponse
	if err := json.Unmarshal(apiResp.Data, &result); err != nil {
		return nil, fmt.Errorf("parse core data: %w", err)
	}

	return &result, nil
}

func callCoreRemovePeer(server *models.VPNServer, pubkey string) error {
	encodedKey := url.PathEscape(pubkey)
	coreURL := fmt.Sprintf("http://%s:%d/api/v1/peers/%s", server.Host, server.Port, encodedKey)

	req, err := http.NewRequest(http.MethodDelete, coreURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Core-Token", server.CoreToken)

	resp, err := coreHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("core unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("core returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
