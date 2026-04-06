-- 000002_peers_constraints.down.sql

BEGIN;

DROP INDEX IF EXISTS idx_peers_expires_at;
DROP INDEX IF EXISTS idx_peers_server_pubkey_active;

COMMIT;
