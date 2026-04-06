-- 000002_peers_constraints.up.sql
-- Add UNIQUE constraint on (server_id, public_key) for active peers
-- and index on expires_at for cleanup queries.

BEGIN;

CREATE UNIQUE INDEX idx_peers_server_pubkey_active
    ON peers (server_id, public_key)
    WHERE is_active = TRUE;

CREATE INDEX idx_peers_expires_at
    ON peers (expires_at)
    WHERE expires_at IS NOT NULL AND is_active = TRUE;

COMMIT;
