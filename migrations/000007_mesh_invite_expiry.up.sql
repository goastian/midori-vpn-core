ALTER TABLE mesh_networks
    ADD COLUMN IF NOT EXISTS invite_expires_at TIMESTAMPTZ DEFAULT NULL;

-- Existing meshes are left with NULL (never expire).
