-- 000018_node_enrollment_identity.up.sql
-- Public Ed25519 identities enrolled by one-use tokens.

BEGIN;

ALTER TABLE core_nodes
    DROP CONSTRAINT chk_core_nodes_name,
    ADD COLUMN identity_public_key BYTEA,
    ADD COLUMN enrolled_at TIMESTAMPTZ,
    ADD CONSTRAINT chk_core_nodes_name CHECK (
        name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    ADD CONSTRAINT chk_core_nodes_identity_key CHECK (
        identity_public_key IS NULL OR octet_length(identity_public_key) = 32
    ),
    ADD CONSTRAINT chk_core_nodes_enrollment_pair CHECK (
        (identity_public_key IS NULL AND enrolled_at IS NULL)
        OR (identity_public_key IS NOT NULL AND enrolled_at IS NOT NULL)
    ),
    ADD CONSTRAINT chk_core_nodes_enrollment_order CHECK (
        enrolled_at IS NULL OR enrolled_at >= created_at
    );

CREATE UNIQUE INDEX uq_core_nodes_identity_public_key
    ON core_nodes (identity_public_key)
    WHERE identity_public_key IS NOT NULL;

COMMIT;
