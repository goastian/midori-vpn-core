BEGIN;

-- Preserve valid auto-session meshes created by earlier builds, but normalize
-- their display name to the new public directory format.
UPDATE mesh_networks
SET country_code = UPPER(substring(name FROM '\[([A-Za-z]{2})\]'))
WHERE country_code = ''
  AND substring(name FROM '\[([A-Za-z]{2})\]') IS NOT NULL;

UPDATE mesh_networks
SET name = 'Servidor mesh random [' || country_code || ']',
    is_session = TRUE,
    updated_at = NOW()
WHERE is_session = TRUE
  AND country_code ~ '^[A-Z]{2}$'
  AND country_code <> 'XX';

-- Remove legacy/manual/unknown-country meshes. Members are removed by cascade.
DELETE FROM mesh_networks
WHERE is_session = FALSE
   OR country_code = ''
   OR country_code = 'XX'
   OR name !~ '^Servidor mesh random \[[A-Z]{2}\]$';

COMMIT;
