UPDATE mesh_networks
SET name = regexp_replace(name, '^Servidor Comunitario', 'Servidor Random')
WHERE is_session = TRUE
  AND name ~ '^Servidor Comunitario';
