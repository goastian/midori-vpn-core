-- Refuse to discard enrolled identities or token audit state.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM core_nodes WHERE identity_public_key IS NOT NULL OR enrolled_at IS NOT NULL)
       OR EXISTS (SELECT 1 FROM node_enrollment_tokens) THEN
        RAISE EXCEPTION 'migration 18 rollback refused: node enrollment state exists';
    END IF;
END
$$;

BEGIN;

DROP INDEX uq_core_nodes_identity_public_key;
ALTER TABLE core_nodes
    DROP CONSTRAINT chk_core_nodes_name,
    DROP CONSTRAINT chk_core_nodes_enrollment_order,
    DROP CONSTRAINT chk_core_nodes_enrollment_pair,
    DROP CONSTRAINT chk_core_nodes_identity_key,
    DROP COLUMN enrolled_at,
    DROP COLUMN identity_public_key,
    ADD CONSTRAINT chk_core_nodes_name CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$');

COMMIT;
