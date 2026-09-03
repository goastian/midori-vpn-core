BEGIN;

DROP INDEX IF EXISTS idx_audit_logs_admin_action_search;
DROP INDEX IF EXISTS idx_audit_logs_admin_action_created;
DROP INDEX IF EXISTS idx_extension_origins_admin_origin;
DROP INDEX IF EXISTS idx_extension_origins_admin_state_updated;
DROP INDEX IF EXISTS idx_mesh_networks_admin_country;
DROP INDEX IF EXISTS idx_mesh_networks_admin_name;
DROP INDEX IF EXISTS idx_mesh_networks_admin_state_created;
DROP INDEX IF EXISTS idx_peers_admin_traffic;
DROP INDEX IF EXISTS idx_peers_admin_last_handshake;
DROP INDEX IF EXISTS idx_peers_admin_assigned_ip;
DROP INDEX IF EXISTS idx_peers_admin_device_name;
DROP INDEX IF EXISTS idx_peers_admin_state_created;
DROP INDEX IF EXISTS idx_vpn_servers_admin_country;
DROP INDEX IF EXISTS idx_vpn_servers_admin_location;
DROP INDEX IF EXISTS idx_vpn_servers_admin_host;
DROP INDEX IF EXISTS idx_vpn_servers_admin_name;
DROP INDEX IF EXISTS idx_vpn_servers_admin_state_created;
DROP INDEX IF EXISTS idx_users_admin_authentik_uid;
DROP INDEX IF EXISTS idx_users_admin_display_name;
DROP INDEX IF EXISTS idx_users_admin_email;
DROP INDEX IF EXISTS idx_users_admin_state_created;

COMMIT;
