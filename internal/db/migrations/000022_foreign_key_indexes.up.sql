-- Add complete leading indexes for every referencing-side foreign key. These
-- protect deletes/updates of parent rows from scanning historical child data.

BEGIN;

CREATE INDEX idx_audit_logs_user_fk
    ON audit_logs (user_id);
CREATE INDEX idx_desired_revisions_previous_fk
    ON desired_revisions (node_id, previous_revision);
CREATE INDEX idx_device_certificates_server_fk
    ON device_certificates (server_id);
CREATE INDEX idx_device_certificates_device_owner_fk
    ON device_certificates (device_id, user_id);
CREATE INDEX idx_mesh_members_peer_fk
    ON mesh_members (peer_id);
CREATE INDEX idx_node_enrollment_tokens_node_fk
    ON node_enrollment_tokens (node_id);
CREATE INDEX idx_node_observations_revision_fk
    ON node_observations (node_id, applied_revision);
CREATE INDEX idx_peer_operations_device_owner_fk
    ON peer_operations (device_id, user_id);
CREATE INDEX idx_peer_operations_previous_peer_fk
    ON peer_operations (previous_peer_id);
CREATE INDEX idx_peers_device_owner_fk
    ON peers (device_id, user_id);
CREATE INDEX idx_peers_provision_operation_fk
    ON peers (provision_operation_id);
CREATE INDEX idx_peers_server_fk
    ON peers (server_id);
CREATE INDEX idx_vpn_servers_node_fk
    ON vpn_servers (node_id);

COMMIT;
