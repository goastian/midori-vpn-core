-- Add country_code to mesh_networks for auto-named session meshes.
ALTER TABLE mesh_networks ADD COLUMN IF NOT EXISTS country_code VARCHAR(2) NOT NULL DEFAULT '';
-- Mark auto-created (session) meshes so they can be cleaned up on logout.
ALTER TABLE mesh_networks ADD COLUMN IF NOT EXISTS is_session BOOLEAN NOT NULL DEFAULT FALSE;
