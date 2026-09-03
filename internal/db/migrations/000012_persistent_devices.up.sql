-- 000012_persistent_devices.up.sql
-- Persistent installation identity separated from historical VPN sessions.

BEGIN;

CREATE TABLE devices (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_instance_id  UUID,
    reported_name       TEXT        NOT NULL,
    alias               TEXT,
    device_type         TEXT        NOT NULL,
    adapter_reference   TEXT,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ,
    CONSTRAINT uq_devices_user_client_instance UNIQUE (user_id, client_instance_id),
    CONSTRAINT uq_devices_id_user UNIQUE (id, user_id),
    CONSTRAINT chk_devices_reported_name CHECK (length(reported_name) BETWEEN 1 AND 64),
    CONSTRAINT chk_devices_alias CHECK (alias IS NULL OR length(alias) BETWEEN 1 AND 64),
    CONSTRAINT chk_devices_type CHECK (device_type IN ('desktop', 'extension', 'manual', 'mobile')),
    CONSTRAINT chk_devices_adapter_reference CHECK (
        adapter_reference IS NULL OR adapter_reference ~ '^net-v1:[A-Za-z0-9_-]{43}$'
    ),
    CONSTRAINT chk_devices_seen_order CHECK (last_seen_at >= first_seen_at),
    CONSTRAINT chk_devices_revoked_order CHECK (revoked_at IS NULL OR revoked_at >= first_seen_at)
);

CREATE INDEX idx_devices_user_last_seen
    ON devices (user_id, last_seen_at DESC);
CREATE INDEX idx_devices_adapter_reference
    ON devices (adapter_reference)
    WHERE adapter_reference IS NOT NULL;
CREATE INDEX idx_devices_user_active
    ON devices (user_id, device_type)
    WHERE revoked_at IS NULL;

ALTER TABLE peers
    ADD COLUMN device_id UUID;

ALTER TABLE device_certificates
    ADD COLUMN device_id UUID;

-- Every active historical peer receives an independent legacy device. Names
-- are deliberately not grouped because equal names do not prove identity.
WITH active_legacy AS MATERIALIZED (
    SELECT
        p.id AS peer_id,
        gen_random_uuid() AS device_id,
        p.user_id,
        LEFT(COALESCE(NULLIF(BTRIM(p.device_name), ''), 'device'), 64) AS reported_name,
        p.created_at AS first_seen_at,
        GREATEST(p.created_at, COALESCE(p.last_handshake, p.created_at)) AS last_seen_at
    FROM peers p
    WHERE p.is_active = TRUE AND p.device_id IS NULL
), inserted_devices AS (
    INSERT INTO devices (
        id, user_id, client_instance_id, reported_name, device_type,
        first_seen_at, last_seen_at
    )
    SELECT
        device_id, user_id, NULL, reported_name, 'manual',
        first_seen_at, last_seen_at
    FROM active_legacy
    RETURNING id
)
UPDATE peers p
SET device_id = legacy.device_id
FROM active_legacy legacy
WHERE p.id = legacy.peer_id
  AND EXISTS (SELECT 1 FROM inserted_devices d WHERE d.id = legacy.device_id);

-- Associate an unrevoked historical certificate with an active peer only
-- when user, server and name identify exactly one device.
WITH certificate_candidates AS (
    SELECT
        c.id AS certificate_id,
        p.device_id
    FROM device_certificates c
    JOIN peers p
      ON p.user_id = c.user_id
     AND p.server_id = c.server_id
     AND lower(p.device_name) = lower(c.device_name)
     AND p.is_active = TRUE
     AND p.device_id IS NOT NULL
    WHERE c.revoked_at IS NULL
), unique_matches AS (
    SELECT
        certificate_id,
        MAX(device_id::text)::UUID AS device_id
    FROM certificate_candidates
    GROUP BY certificate_id
    HAVING COUNT(DISTINCT device_id) = 1
)
UPDATE device_certificates c
SET device_id = matches.device_id
FROM unique_matches matches
WHERE c.id = matches.certificate_id;

-- Remaining unrevoked certificates get independent legacy devices. This
-- preserves access and avoids unsafe grouping across equal hostnames.
WITH unmatched_certificates AS MATERIALIZED (
    SELECT
        c.id AS certificate_id,
        gen_random_uuid() AS device_id,
        c.user_id,
        c.device_name AS reported_name,
        c.created_at AS first_seen_at
    FROM device_certificates c
    WHERE c.revoked_at IS NULL AND c.device_id IS NULL
), inserted_devices AS (
    INSERT INTO devices (
        id, user_id, client_instance_id, reported_name, device_type,
        first_seen_at, last_seen_at
    )
    SELECT
        device_id, user_id, NULL, reported_name, 'manual',
        first_seen_at, first_seen_at
    FROM unmatched_certificates
    RETURNING id
)
UPDATE device_certificates c
SET device_id = legacy.device_id
FROM unmatched_certificates legacy
WHERE c.id = legacy.certificate_id
  AND EXISTS (SELECT 1 FROM inserted_devices d WHERE d.id = legacy.device_id);

ALTER TABLE peers
    ADD CONSTRAINT fk_peers_device_owner
        FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT chk_peers_active_device
    CHECK (is_active = FALSE OR device_id IS NOT NULL);

ALTER TABLE device_certificates
    ADD CONSTRAINT fk_device_certificates_device_owner
        FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id)
        DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT chk_device_certificates_current_device
        CHECK (revoked_at IS NOT NULL OR device_id IS NOT NULL);

CREATE UNIQUE INDEX uq_peers_active_device
    ON peers (device_id)
    WHERE is_active = TRUE AND device_id IS NOT NULL;
CREATE INDEX idx_peers_device_created
    ON peers (device_id, created_at DESC)
    WHERE device_id IS NOT NULL;

DROP INDEX uq_device_certificates_active_device;
CREATE UNIQUE INDEX uq_device_certificates_active_device_id
    ON device_certificates (device_id, server_id)
    WHERE revoked_at IS NULL AND device_id IS NOT NULL;
CREATE INDEX idx_device_certificates_device_created
    ON device_certificates (device_id, created_at DESC)
    WHERE device_id IS NOT NULL;

COMMIT;
