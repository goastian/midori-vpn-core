BEGIN;

UPDATE mesh_networks
SET name = 'Servidor mesh random [' || country_code || ']',
    updated_at = NOW()
WHERE is_session = TRUE
  AND country_code ~ '^[A-Z]{2}$'
  AND country_code <> 'XX';

COMMIT;
