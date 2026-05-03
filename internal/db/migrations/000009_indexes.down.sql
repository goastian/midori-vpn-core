BEGIN;

DROP INDEX IF EXISTS idx_audit_logs_created_at;
DROP INDEX IF EXISTS idx_vpn_servers_is_active;
DROP INDEX IF EXISTS idx_peers_created_at;
DROP INDEX IF EXISTS idx_peers_assigned_ip;
DROP INDEX IF EXISTS idx_peers_is_active;
DROP INDEX IF EXISTS idx_peers_public_key;

COMMIT;
