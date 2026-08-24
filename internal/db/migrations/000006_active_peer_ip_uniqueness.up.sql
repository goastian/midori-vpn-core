BEGIN;

ALTER TABLE peers
    DROP CONSTRAINT IF EXISTS uq_peers_server_assigned_ip;

DROP INDEX IF EXISTS uq_peers_active_server_assigned_ip;

CREATE UNIQUE INDEX uq_peers_active_server_assigned_ip
    ON peers (server_id, assigned_ip)
    WHERE is_active = TRUE;

COMMIT;
