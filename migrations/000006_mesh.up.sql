-- 000006_mesh.up.sql
-- Mesh networking: mesh_networks and mesh_members tables

BEGIN;

-- ============================================================
-- Table: mesh_networks
-- Each row is a named private overlay network. The owner
-- auto-assigns a /24 subnet from the 10.200.0.0/16 range.
-- Members communicate with each other through their mesh IPs.
-- ============================================================
CREATE TABLE mesh_networks (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL,
    description  TEXT        NOT NULL DEFAULT '',
    owner_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subnet       TEXT        NOT NULL,                          -- e.g. "10.200.1.0/24"
    invite_code  TEXT        NOT NULL UNIQUE,
    max_members  INTEGER     NOT NULL DEFAULT 10,
    is_active    BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mesh_networks_owner  ON mesh_networks (owner_id);
CREATE INDEX idx_mesh_networks_invite ON mesh_networks (invite_code);

-- ============================================================
-- Table: mesh_members
-- Each row links a user (and optionally their active VPN peer)
-- to a mesh network with an assigned mesh IP.
-- ============================================================
CREATE TABLE mesh_members (
    id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    mesh_id   UUID        NOT NULL REFERENCES mesh_networks(id) ON DELETE CASCADE,
    user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    peer_id   UUID        REFERENCES peers(id) ON DELETE SET NULL,
    mesh_ip   TEXT        NOT NULL,           -- host address in the mesh subnet, e.g. "10.200.1.2"
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(mesh_id, user_id),
    UNIQUE(mesh_id, mesh_ip)
);

CREATE INDEX idx_mesh_members_mesh   ON mesh_members (mesh_id);
CREATE INDEX idx_mesh_members_user   ON mesh_members (user_id);

COMMIT;
