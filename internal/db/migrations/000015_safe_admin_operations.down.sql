-- 000015_safe_admin_operations.down.sql

BEGIN;

DROP INDEX IF EXISTS idx_peer_operations_previous_peer_live;
DROP INDEX IF EXISTS idx_peer_operations_user_live;
DROP INDEX IF EXISTS idx_peers_server_active;
DROP INDEX IF EXISTS idx_peers_user_active;

ALTER TABLE vpn_servers
    DROP COLUMN draining_at;

COMMIT;
