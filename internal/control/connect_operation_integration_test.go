package control_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/goastian/midori-vpn-core/internal/config"
	"github.com/goastian/midori-vpn-core/internal/control"
	"github.com/goastian/midori-vpn-core/internal/models"
)

func connectOperationKey(fill byte) string {
	key := make([]byte, 32)
	for index := range key {
		key[index] = fill
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestConnectPendingOperationReturnsRetryableConflict(t *testing.T) {
	pool := handlerTestPool(t)
	user := insertUser(t, pool)
	ctx := context.Background()

	var serverID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO vpn_servers (name, host, current_peers)
		VALUES ($1, 'pending-operation.test.invalid', 1)
		RETURNING id`, "Pending "+uuid.NewString()).Scan(&serverID); err != nil {
		t.Fatalf("insert operation server: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM vpn_servers WHERE id = $1`, serverID) })

	clientInstanceID := uuid.New()
	var deviceID uuid.UUID
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (user_id, client_instance_id, reported_name, device_type)
		VALUES ($1, $2, 'pending-host', 'desktop')
		RETURNING id`, user.ID, clientInstanceID).Scan(&deviceID); err != nil {
		t.Fatalf("insert operation device: %v", err)
	}
	operationID := uuid.New()
	publicKey := connectOperationKey(42)
	if _, err := pool.Exec(ctx, `
		INSERT INTO peer_operations (
			id, action, state, user_id, device_id, server_id, public_key,
			capacity_reserved, attempts
		) VALUES ($1, 'connect', 'pending', $2, $3, $4, $5, TRUE, 1)`,
		operationID, user.ID, deviceID, serverID, publicKey); err != nil {
		t.Fatalf("insert pending operation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			UPDATE peer_operations
			SET state = 'failed', capacity_reserved = FALSE
			WHERE id = $1`, operationID)
	})

	handler := control.NewHandler(pool, &config.Config{MaxDevicesPerUser: 5})
	request := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/control/connections", jsonBody(t, map[string]any{
		"server_id":  serverID.String(),
		"public_key": publicKey,
		"device": map[string]any{
			"client_instance_id": clientInstanceID.String(),
			"reported_name":      "pending-host",
			"device_type":        models.DeviceTypeDesktop,
		},
	})), user)
	recorder := httptest.NewRecorder()
	handler.Connect(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("Connect status = %d, want 409: %s", recorder.Code, recorder.Body.String())
	}
	if retryAfter := recorder.Header().Get("Retry-After"); retryAfter != "5" {
		t.Fatalf("Retry-After = %q, want 5", retryAfter)
	}
	var failure struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&failure); err != nil {
		t.Fatalf("decode pending response: %v", err)
	}
	if failure.Code != "connection_in_progress" {
		t.Fatalf("response code = %q, want connection_in_progress", failure.Code)
	}
}
