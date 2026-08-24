BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'mesh_networks' AND column_name = 'invite_expires'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'mesh_networks' AND column_name = 'invite_expires_at'
    ) THEN
        ALTER TABLE mesh_networks RENAME COLUMN invite_expires TO invite_expires_at;
    END IF;
END $$;

COMMIT;
