BEGIN;

-- Exit-node negotiation requires an explicit proxy protocol and transport
-- capabilities. Existing installations never received these columns even
-- though the repository queries already depend on them.
ALTER TABLE mesh_members
    ADD COLUMN proxy_scheme VARCHAR(20) NOT NULL DEFAULT 'socks5',
    ADD COLUMN supports_tcp BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN supports_udp BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE mesh_members
    ADD CONSTRAINT chk_mesh_members_proxy_scheme
    CHECK (proxy_scheme IN ('socks5', 'http-connect'));

ALTER TABLE user_exit_node
    ADD COLUMN proxy_scheme VARCHAR(20) NOT NULL DEFAULT 'socks5',
    ADD COLUMN supports_tcp BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN supports_udp BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE user_exit_node
    ADD CONSTRAINT chk_user_exit_node_proxy_scheme
    CHECK (proxy_scheme IN ('socks5', 'http-connect'));

COMMIT;
