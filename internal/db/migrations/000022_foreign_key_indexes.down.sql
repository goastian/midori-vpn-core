BEGIN;

DROP INDEX IF EXISTS idx_vpn_servers_node_fk;
DROP INDEX IF EXISTS idx_peers_server_fk;
DROP INDEX IF EXISTS idx_peers_provision_operation_fk;
DROP INDEX IF EXISTS idx_peers_device_owner_fk;
DROP INDEX IF EXISTS idx_peer_operations_previous_peer_fk;
DROP INDEX IF EXISTS idx_peer_operations_device_owner_fk;
DROP INDEX IF EXISTS idx_node_observations_revision_fk;
DROP INDEX IF EXISTS idx_node_enrollment_tokens_node_fk;
DROP INDEX IF EXISTS idx_mesh_members_peer_fk;
DROP INDEX IF EXISTS idx_device_certificates_device_owner_fk;
DROP INDEX IF EXISTS idx_device_certificates_server_fk;
DROP INDEX IF EXISTS idx_desired_revisions_previous_fk;
DROP INDEX IF EXISTS idx_audit_logs_user_fk;

COMMIT;
