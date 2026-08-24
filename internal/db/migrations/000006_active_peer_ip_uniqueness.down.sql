BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM peers
        GROUP BY server_id, assigned_ip
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot restore peer IP uniqueness while duplicate historical allocations exist';
    END IF;
END $$;

DROP INDEX IF EXISTS uq_peers_active_server_assigned_ip;

ALTER TABLE peers
    ADD CONSTRAINT uq_peers_server_assigned_ip UNIQUE (server_id, assigned_ip);

COMMIT;
