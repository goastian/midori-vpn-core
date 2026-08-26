BEGIN;

-- Client private keys never enter this database. Core stores only the signed
-- certificate and a fingerprint of the public key supplied in a verified CSR.
CREATE TABLE device_certificates (
    id                  UUID        PRIMARY KEY,
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id           UUID        NOT NULL REFERENCES vpn_servers(id) ON DELETE CASCADE,
    device_name         TEXT        NOT NULL,
    serial_number       TEXT        NOT NULL UNIQUE,
    certificate_pem     TEXT        NOT NULL,
    public_key_sha256   TEXT        NOT NULL,
    not_before          TIMESTAMPTZ NOT NULL,
    not_after           TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (length(device_name) BETWEEN 1 AND 64),
    CHECK (length(serial_number) BETWEEN 2 AND 64),
    CHECK (length(public_key_sha256) = 64),
    CHECK (not_after > not_before)
);

CREATE UNIQUE INDEX uq_device_certificates_active_device
    ON device_certificates (user_id, server_id, lower(device_name))
    WHERE revoked_at IS NULL;
CREATE INDEX idx_device_certificates_user_created
    ON device_certificates (user_id, created_at DESC);
CREATE INDEX idx_device_certificates_active_expiry
    ON device_certificates (not_after)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_device_certificates_revoked
    ON device_certificates (revoked_at)
    WHERE revoked_at IS NOT NULL;

COMMIT;
