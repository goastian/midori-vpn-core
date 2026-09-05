\set ON_ERROR_STOP on

\getenv database_name POSTGRES_DB
\getenv owner_role POSTGRES_OWNER_ROLE
\getenv migrator_role POSTGRES_MIGRATOR_USER
\getenv runtime_role POSTGRES_RUNTIME_USER
\getenv backup_role POSTGRES_BACKUP_USER

SELECT (
    current_setting('password_encryption') = 'scram-sha-256'
    AND position('pg_stat_statements' IN current_setting('shared_preload_libraries')) > 0
    AND EXISTS (SELECT FROM pg_extension WHERE extname = 'pg_stat_statements')
    AND EXISTS (
        SELECT FROM pg_roles
        WHERE rolname = :'owner_role'
          AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
          AND NOT rolcreaterole AND NOT rolreplication
    )
    AND EXISTS (
        SELECT FROM pg_roles
        WHERE rolname = :'migrator_role'
          AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
          AND NOT rolcreaterole AND NOT rolreplication
    )
    AND EXISTS (
        SELECT FROM pg_roles
        WHERE rolname = :'runtime_role'
          AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
          AND NOT rolcreaterole AND NOT rolreplication
    )
    AND EXISTS (
        SELECT FROM pg_roles
        WHERE rolname = :'backup_role'
          AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
          AND NOT rolcreaterole AND NOT rolreplication
    )
    AND pg_has_role(:'migrator_role', :'owner_role', 'MEMBER')
    AND pg_has_role(:'backup_role', 'pg_read_all_data', 'MEMBER')
    AND (SELECT pg_get_userbyid(datdba) = :'owner_role' FROM pg_database WHERE datname = :'database_name')
    AND has_database_privilege(:'runtime_role', :'database_name', 'CONNECT')
    AND NOT has_database_privilege(:'runtime_role', :'database_name', 'TEMPORARY')
    AND has_schema_privilege(:'runtime_role', 'public', 'USAGE')
    AND NOT has_schema_privilege(:'runtime_role', 'public', 'CREATE')
    AND NOT EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
          AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = :'owner_role')
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend d
              WHERE d.classid = 'pg_class'::regclass
                AND d.objid = c.oid
                AND d.deptype = 'e'
          )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proowner <> (SELECT oid FROM pg_roles WHERE rolname = :'owner_role')
          AND NOT EXISTS (
              SELECT 1
              FROM pg_depend d
              WHERE d.classid = 'pg_proc'::regclass
                AND d.objid = p.oid
                AND d.deptype = 'e'
          )
    )
    AND has_database_privilege(:'backup_role', :'database_name', 'CONNECT')
    AND NOT has_database_privilege(:'backup_role', :'database_name', 'TEMPORARY')
    AND NOT EXISTS (
        SELECT FROM pg_hba_file_rules
        WHERE error IS NOT NULL
           OR (type IN ('local', 'host', 'hostssl', 'hostnossl') AND auth_method <> 'scram-sha-256')
    )
) AS policy_ok
\gset

\if :policy_ok
\else
  DO $$
  BEGIN
      RAISE EXCEPTION 'PostgreSQL hardening policy validation failed';
  END
  $$;
\endif
