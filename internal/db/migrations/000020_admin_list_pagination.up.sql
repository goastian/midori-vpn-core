-- Support bounded administrative list filters and deterministic ordering.

BEGIN;

CREATE INDEX idx_users_admin_state_created
    ON users (is_banned, created_at DESC, id DESC);
CREATE INDEX idx_users_admin_email
    ON users (lower(email) text_pattern_ops, id);
CREATE INDEX idx_users_admin_display_name
    ON users (lower(display_name) text_pattern_ops, id);
CREATE INDEX idx_users_admin_authentik_uid
    ON users (lower(authentik_uid) text_pattern_ops, id);

CREATE INDEX idx_vpn_servers_admin_state_created
    ON vpn_servers (is_active, (draining_at IS NOT NULL), created_at DESC, id DESC);
CREATE INDEX idx_vpn_servers_admin_name
    ON vpn_servers (lower(name) text_pattern_ops, id);
CREATE INDEX idx_vpn_servers_admin_host
    ON vpn_servers (lower(host) text_pattern_ops, id);
CREATE INDEX idx_vpn_servers_admin_location
    ON vpn_servers (lower(location) text_pattern_ops, id);
CREATE INDEX idx_vpn_servers_admin_country
    ON vpn_servers (lower(country_code) text_pattern_ops, id);

CREATE INDEX idx_peers_admin_state_created
    ON peers (is_active, created_at DESC, id DESC);
CREATE INDEX idx_peers_admin_device_name
    ON peers (lower(device_name) text_pattern_ops, id);
CREATE INDEX idx_peers_admin_assigned_ip
    ON peers (assigned_ip text_pattern_ops, id);
CREATE INDEX idx_peers_admin_last_handshake
    ON peers (last_handshake DESC NULLS LAST, id DESC);
CREATE INDEX idx_peers_admin_traffic
    ON peers ((bytes_sent + bytes_received) DESC, id DESC);

CREATE INDEX idx_mesh_networks_admin_state_created
    ON mesh_networks (is_active, created_at DESC, id DESC) WHERE is_session = TRUE;
CREATE INDEX idx_mesh_networks_admin_name
    ON mesh_networks (lower(name) text_pattern_ops, id) WHERE is_session = TRUE;
CREATE INDEX idx_mesh_networks_admin_country
    ON mesh_networks (lower(country_code) text_pattern_ops, id) WHERE is_session = TRUE;

CREATE INDEX idx_extension_origins_admin_state_updated
    ON trusted_extension_origins (revoked, updated_at DESC, id DESC);
CREATE INDEX idx_extension_origins_admin_origin
    ON trusted_extension_origins (lower(origin) text_pattern_ops, id);

CREATE INDEX idx_audit_logs_admin_action_created
    ON audit_logs (action, created_at DESC, id DESC);
CREATE INDEX idx_audit_logs_admin_action_search
    ON audit_logs (lower(action) text_pattern_ops, id);

COMMIT;
