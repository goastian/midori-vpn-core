package control_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/models"
	"github.com/goastian/midori-vpn-core/internal/proxytoken"
	"github.com/goastian/midori-vpn-core/internal/repo"
)

func TestTransportCredentialsBindPersistentDeviceServerAndCluster(t *testing.T) {
	pool := handlerTestPool(t)
	ctx := context.Background()
	user := insertUser(t, pool)
	multicluster := repo.NewMulticlusterRepo(pool)
	serverRepo := repo.NewServerRepo(pool)

	cluster := &models.Cluster{Name: "credentials-" + uuid.NewString(), Region: "test", State: models.ClusterStateActive}
	if err := multicluster.CreateCluster(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	node := &models.CoreNode{
		ClusterID: cluster.ID, Name: "credentials-" + uuid.NewString()[:8],
		ManagementHost: uuid.NewString() + ".nodes.test.invalid", State: models.ClusterStateActive,
	}
	if err := multicluster.CreateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	identity := make([]byte, ed25519.PublicKeySize)
	if _, err := rand.Read(identity); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE core_nodes
		SET identity_public_key = $2, enrolled_at = NOW(), core_version = '2.0.0', last_seen_at = NOW()
		WHERE id = $1`, node.ID, identity); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	server := &models.VPNServer{
		Name: "Credentials " + uuid.NewString(), Host: "credentials.test.invalid", Endpoint: "credentials.test.invalid",
		Port: 8443, WGPort: 51820, PublicKey: "test", Location: "Test", CountryCode: "ZZ", MaxPeers: 10, IsActive: true,
	}
	transports := []models.TransportCapability{
		{Protocol: "wireguard", Host: "credentials.test.invalid", Port: 51820, Enabled: true, Priority: 10, HealthStatus: "healthy", LastChecked: &now},
		{Protocol: "wss", Host: "credentials.test.invalid", Port: 443, Enabled: true, Priority: 20, HealthStatus: "healthy", LastChecked: &now},
		{Protocol: "proxy", Host: "credentials.test.invalid", Port: 8443, Enabled: true, Priority: 30, HealthStatus: "healthy", LastChecked: &now},
	}
	if err := serverRepo.CreateWithTransports(ctx, server, transports); err != nil {
		t.Fatal(err)
	}
	if err := multicluster.BindServer(ctx, server.ID, node.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO desired_revisions (
			node_id, revision, schema_version, minimum_core_version, payload,
			payload_sha256, signature, signing_key_id, issued_at, expires_at
		) VALUES ($1, 1, 1, '2.0.0',
			'{"transports":[{"enabled":true,"protocol":"proxy"},{"enabled":true,"protocol":"wireguard"},{"enabled":true,"protocol":"wss"}]}'::jsonb,
			$2, $3, 'control', NOW(), NOW() + INTERVAL '15 minutes')`,
		node.ID, make([]byte, 32), make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if err := multicluster.RecordObservation(ctx, &models.NodeObservation{
		NodeID: node.ID, AppliedRevision: int64Pointer(1), CoreVersion: "2.0.0", HealthStatus: "healthy",
		VersionCompatible: true, MaxPeers: 10,
		TransportStates: map[string]models.NodeTransportState{
			"wireguard": {Status: "healthy", Certified: false},
			"wss":       {Status: "healthy", Certified: false},
			"proxy":     {Status: "healthy", Certified: false},
		},
		ReportedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM peers WHERE server_id = $1`, server.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE user_id = $1`, user.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, server.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM node_observations WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM desired_revisions WHERE node_id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM core_nodes WHERE id = $1`, node.ID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster.ID)
	})

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPrivate := base64.RawURLEncoding.EncodeToString(privateKey)
	encodedPublic := base64.RawURLEncoding.EncodeToString(publicKey)
	handler := control.NewHandler(pool, &config.Config{
		ControlNodeID: "control", ControlNodePrivateKey: encodedPrivate,
		TransportTokenIssuer: "https://control.test",
	})
	verifier, err := proxytoken.NewVerifier("https://control.test", "control="+encodedPublic, false, "")
	if err != nil {
		t.Fatal(err)
	}
	clientInstanceID := uuid.New()
	proxyRequest := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/control/proxy-credentials", jsonBody(t, map[string]any{
		"server_id": server.ID,
		"device": map[string]any{
			"client_instance_id": clientInstanceID,
			"reported_name":      "Browser test",
			"device_type":        "extension",
		},
	})), user)
	proxyRecorder := httptest.NewRecorder()
	handler.ProxyCredentials(proxyRecorder, proxyRequest)
	if proxyRecorder.Code != http.StatusOK || proxyRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("proxy credential status/cache = %d/%q; body=%s", proxyRecorder.Code, proxyRecorder.Header().Get("Cache-Control"), proxyRecorder.Body.String())
	}
	proxyResponse := decodeResponseData[struct {
		ProxyToken string    `json:"proxy_token"`
		DeviceID   uuid.UUID `json:"device_id"`
	}](t, proxyRecorder)
	proxyClaims, err := verifier.Verify(proxyResponse.ProxyToken, proxytoken.AudienceVPNProxy, server.ID, cluster.ID)
	if err != nil || proxyClaims.UserID != user.ID || proxyClaims.DeviceID != proxyResponse.DeviceID {
		t.Fatalf("proxy claims = %#v, %v", proxyClaims, err)
	}

	peerID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO peers (id, user_id, server_id, public_key, assigned_ip, device_name, device_id)
		VALUES ($1, $2, $3, $4, '10.80.0.2/32', 'Browser test', $5)`,
		peerID, user.ID, server.ID, base64.StdEncoding.EncodeToString(make([]byte, 32)), proxyResponse.DeviceID); err != nil {
		t.Fatal(err)
	}
	tunnelRequest := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/control/tunnel-credentials", jsonBody(t, map[string]any{"peer_id": peerID})), user)
	tunnelRecorder := httptest.NewRecorder()
	handler.TunnelCredentials(tunnelRecorder, tunnelRequest)
	if tunnelRecorder.Code != http.StatusOK {
		t.Fatalf("tunnel credential status = %d; body=%s", tunnelRecorder.Code, tunnelRecorder.Body.String())
	}
	tunnelResponse := decodeResponseData[struct {
		TunnelToken string `json:"tunnel_token"`
	}](t, tunnelRecorder)
	tunnelClaims, err := verifier.Verify(tunnelResponse.TunnelToken, proxytoken.AudienceVPNTunnel, server.ID, cluster.ID)
	if err != nil || tunnelClaims.DeviceID != proxyResponse.DeviceID || tunnelClaims.DeviceID == peerID {
		t.Fatalf("tunnel device claim = %#v, %v", tunnelClaims, err)
	}

	var persistedClientID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT client_instance_id FROM devices WHERE id = $1`, proxyResponse.DeviceID).Scan(&persistedClientID); err != nil || persistedClientID != clientInstanceID {
		t.Fatalf("persisted installation ID = %s, %v", persistedClientID, err)
	}
}

func int64Pointer(value int64) *int64 { return &value }
