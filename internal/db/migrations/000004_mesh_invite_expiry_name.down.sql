BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'mesh_networks' AND column_name = 'invite_expires_at'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'mesh_networks' AND column_name = 'invite_expires'
    ) THEN
        ALTER TABLE mesh_networks RENAME COLUMN invite_expires_at TO invite_expires;
    END IF;
END $$;

COMMIT;
