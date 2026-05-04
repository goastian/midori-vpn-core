UPDATE mesh_networks
SET name = regexp_replace(name, '^Servidor Random', 'Servidor Comunitario')
WHERE is_session = TRUE
  AND name ~ '^Servidor Random';
