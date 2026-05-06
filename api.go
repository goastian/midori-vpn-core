package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type MeshNodeStatus struct {
	Active   bool    `json:"active"`
	MeshIP   string  `json:"mesh_ip,omitempty"`
	MeshID   string  `json:"mesh_id,omitempty"`
	PublicIP string  `json:"public_ip,omitempty"`
	Peers    []Peer  `json:"peers"`
}

type Peer struct {
	MeshIP      string `json:"mesh_ip"`
	DisplayName string `json:"display_name,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
}

type MidoriAPI struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func NewMidoriAPI(url, token string) *MidoriAPI {
	return &MidoriAPI{
		BaseURL: url,
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (a *MidoriAPI) doRequest(method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		bodyReader = bytes.NewBuffer(data)
	}

	req, err := http.NewRequest(method, a.BaseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("api error %d: %s", resp.StatusCode, string(resBody))
	}

	return resBody, nil
}

func (a *MidoriAPI) ActivateMesh() (*MeshNodeStatus, error) {
	data, err := a.doRequest("POST", "/api/v1/control/mesh/node", nil)
	if err != nil {
		return nil, err
	}
	var s MeshNodeStatus
	json.Unmarshal(data, &s)
	return &s, nil
}

func (a *MidoriAPI) GetStatus() (*MeshNodeStatus, error) {
	data, err := a.doRequest("GET", "/api/v1/control/mesh/node", nil)
	if err != nil {
		return nil, err
	}
	var s MeshNodeStatus
	json.Unmarshal(data, &s)
	return &s, nil
}
