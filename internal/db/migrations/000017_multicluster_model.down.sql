-- 000017_multicluster_model.down.sql
-- Refuse to discard durable cluster state after the model has been used.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM clusters)
       OR EXISTS (SELECT 1 FROM core_nodes)
       OR EXISTS (SELECT 1 FROM node_enrollment_tokens)
       OR EXISTS (SELECT 1 FROM desired_revisions)
       OR EXISTS (SELECT 1 FROM node_observations)
       OR EXISTS (SELECT 1 FROM vpn_servers WHERE node_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 17 rollback refused: durable multicluster state exists';
    END IF;
END
$$;

BEGIN;

DROP FUNCTION vpn_server_placement_eligible(UUID, TEXT, INTERVAL, BOOLEAN);

DROP INDEX idx_vpn_servers_legacy_unbound;
DROP INDEX uq_vpn_servers_node;
ALTER TABLE vpn_servers
    DROP CONSTRAINT chk_vpn_servers_node_binding,
    DROP COLUMN legacy_node_unbound,
    DROP COLUMN node_id;

DROP TABLE node_observations;
DROP TABLE desired_revisions;
DROP TABLE node_enrollment_tokens;
DROP TABLE core_nodes;
DROP TABLE clusters;

COMMIT;
