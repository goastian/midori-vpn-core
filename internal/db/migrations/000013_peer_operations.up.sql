-- 000013_peer_operations.up.sql
-- Durable lifecycle for idempotent WireGuard peer provisioning.

BEGIN;

CREATE TABLE peer_operations (
    id                  UUID        PRIMARY KEY,
    action              TEXT        NOT NULL,
    state               TEXT        NOT NULL,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id           UUID        NOT NULL,
    server_id           UUID        NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    public_key          TEXT        NOT NULL,
    preshared_key       TEXT        NOT NULL DEFAULT '',
    pq_kem_ciphertext   TEXT        NOT NULL DEFAULT '',
    previous_peer_id    UUID        REFERENCES peers(id) ON DELETE SET NULL,
    assigned_ip         TEXT,
    capacity_reserved   BOOLEAN     NOT NULL DEFAULT FALSE,
    attempts            INTEGER     NOT NULL DEFAULT 0,
    last_error          TEXT        NOT NULL DEFAULT '',
    core_applied_at     TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_peer_operations_device_owner
        FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT chk_peer_operations_action
        CHECK (action IN ('connect', 'replace', 'disconnect')),
    CONSTRAINT chk_peer_operations_state
        CHECK (state IN ('pending', 'core_applied', 'completed', 'cleanup_pending', 'failed')),
    CONSTRAINT chk_peer_operations_public_key
        CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),
    CONSTRAINT chk_peer_operations_attempts CHECK (attempts >= 0),
    CONSTRAINT chk_peer_operations_error_length CHECK (length(last_error) <= 1024),
    CONSTRAINT chk_peer_operations_applied_data CHECK (
        state NOT IN ('core_applied', 'completed', 'cleanup_pending')
        OR (assigned_ip IS NOT NULL AND core_applied_at IS NOT NULL)
    ),
    CONSTRAINT chk_peer_operations_completion CHECK (
        state NOT IN ('completed', 'cleanup_pending') OR completed_at IS NOT NULL
    )
);

CREATE UNIQUE INDEX uq_peer_operations_live_device
    ON peer_operations (device_id)
    WHERE state IN ('pending', 'core_applied', 'cleanup_pending');
CREATE UNIQUE INDEX uq_peer_operations_live_key
    ON peer_operations (public_key)
    WHERE state IN ('pending', 'core_applied', 'cleanup_pending');
CREATE INDEX idx_peer_operations_state_updated
    ON peer_operations (state, updated_at);
CREATE INDEX idx_peer_operations_user_created
    ON peer_operations (user_id, created_at DESC);
CREATE INDEX idx_peer_operations_server_state
    ON peer_operations (server_id, state);

ALTER TABLE peers
    ADD COLUMN provision_operation_id UUID,
    ADD CONSTRAINT fk_peers_provision_operation
        FOREIGN KEY (provision_operation_id) REFERENCES peer_operations(id)
        DEFERRABLE INITIALLY DEFERRED;

CREATE UNIQUE INDEX uq_peers_provision_operation
    ON peers (provision_operation_id)
    WHERE provision_operation_id IS NOT NULL;

CREATE FUNCTION prevent_delete_with_live_peer_operation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'users' AND EXISTS (
        SELECT 1 FROM peer_operations
        WHERE user_id = OLD.id
          AND state IN ('pending', 'core_applied', 'cleanup_pending')
    ) THEN
        RAISE EXCEPTION 'user has a pending peer operation' USING ERRCODE = '55000';
    ELSIF TG_TABLE_NAME = 'devices' AND EXISTS (
        SELECT 1 FROM peer_operations
        WHERE device_id = OLD.id
          AND state IN ('pending', 'core_applied', 'cleanup_pending')
    ) THEN
        RAISE EXCEPTION 'device has a pending peer operation' USING ERRCODE = '55000';
    ELSIF TG_TABLE_NAME = 'vpn_servers' AND EXISTS (
        SELECT 1 FROM peer_operations
        WHERE server_id = OLD.id
          AND state IN ('pending', 'core_applied', 'cleanup_pending')
    ) THEN
        RAISE EXCEPTION 'server has a pending peer operation' USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_users_live_peer_operation
    BEFORE DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION prevent_delete_with_live_peer_operation();
CREATE TRIGGER trg_devices_live_peer_operation
    BEFORE DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION prevent_delete_with_live_peer_operation();
CREATE TRIGGER trg_servers_live_peer_operation
    BEFORE DELETE ON vpn_servers
    FOR EACH ROW EXECUTE FUNCTION prevent_delete_with_live_peer_operation();

COMMIT;
