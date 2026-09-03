-- 000013_peer_operations.down.sql

BEGIN;

DROP TRIGGER IF EXISTS trg_servers_live_peer_operation ON vpn_servers;
DROP TRIGGER IF EXISTS trg_devices_live_peer_operation ON devices;
DROP TRIGGER IF EXISTS trg_users_live_peer_operation ON users;
DROP FUNCTION IF EXISTS prevent_delete_with_live_peer_operation();

DROP INDEX IF EXISTS uq_peers_provision_operation;
ALTER TABLE peers
    DROP CONSTRAINT IF EXISTS fk_peers_provision_operation,
    DROP COLUMN IF EXISTS provision_operation_id;

DROP TABLE peer_operations;

COMMIT;
