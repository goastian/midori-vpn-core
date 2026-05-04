BEGIN;

UPDATE mesh_networks
SET name = 'Servidor Random ' ||
           chr(127397 + ascii(substr(country_code, 1, 1))) ||
           chr(127397 + ascii(substr(country_code, 2, 1))) ||
           ' [' || country_code || ']',
    updated_at = NOW()
WHERE is_session = TRUE
  AND country_code ~ '^[A-Z]{2}$'
  AND country_code <> 'XX';

COMMIT;
