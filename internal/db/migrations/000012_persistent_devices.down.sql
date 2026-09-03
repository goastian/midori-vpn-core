-- 000012_persistent_devices.down.sql

BEGIN;

-- The previous schema cannot represent two active certificates with the same
-- user/server/name. Refuse an unsafe rollback instead of revoking data.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM device_certificates
        WHERE revoked_at IS NULL
        GROUP BY user_id, server_id, lower(device_name)
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot roll back persistent devices while duplicate active certificate names exist';
    END IF;
END
$$;

DROP INDEX IF EXISTS idx_device_certificates_device_created;
DROP INDEX IF EXISTS uq_device_certificates_active_device_id;
DROP INDEX IF EXISTS idx_peers_device_created;
DROP INDEX IF EXISTS uq_peers_active_device;

ALTER TABLE peers
    DROP CONSTRAINT IF EXISTS chk_peers_active_device,
    DROP COLUMN IF EXISTS device_id;

ALTER TABLE device_certificates
    DROP COLUMN IF EXISTS device_id;

CREATE UNIQUE INDEX uq_device_certificates_active_device
    ON device_certificates (user_id, server_id, lower(device_name))
    WHERE revoked_at IS NULL;

DROP TABLE devices;

COMMIT;
