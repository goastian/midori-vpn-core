-- 000015_safe_admin_operations.up.sql
-- Durable server draining and indexes used by administrative convergence.

BEGIN;

ALTER TABLE vpn_servers
    ADD COLUMN draining_at TIMESTAMPTZ;

CREATE INDEX idx_peers_user_active
    ON peers (user_id)
    WHERE is_active = TRUE;

CREATE INDEX idx_peers_server_active
    ON peers (server_id)
    WHERE is_active = TRUE;

CREATE INDEX idx_peer_operations_user_live
    ON peer_operations (user_id)
    WHERE state IN ('pending', 'core_applied', 'cleanup_pending');

CREATE INDEX idx_peer_operations_previous_peer_live
    ON peer_operations (previous_peer_id)
    WHERE previous_peer_id IS NOT NULL
      AND state IN ('pending', 'core_applied', 'cleanup_pending');

COMMIT;
