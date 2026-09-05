\set ON_ERROR_STOP on

\getenv database_name POSTGRES_DB
\getenv admin_role POSTGRES_ADMIN_USER
\getenv owner_role POSTGRES_OWNER_ROLE
\getenv migrator_role POSTGRES_MIGRATOR_USER
\getenv migrator_password POSTGRES_MIGRATOR_PASSWORD
\getenv runtime_role POSTGRES_RUNTIME_USER
\getenv runtime_password POSTGRES_RUNTIME_PASSWORD
\getenv backup_role POSTGRES_BACKUP_USER
\getenv backup_password POSTGRES_BACKUP_PASSWORD

SELECT format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', :'owner_role')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'owner_role') \gexec

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L', :'migrator_role', :'migrator_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'migrator_role') \gexec

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L', :'runtime_role', :'runtime_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'runtime_role') \gexec

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L', :'backup_role', :'backup_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'backup_role') \gexec

SELECT format('ALTER ROLE %I PASSWORD %L', :'migrator_role', :'migrator_password') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'runtime_role', :'runtime_password') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'backup_role', :'backup_password') \gexec
SELECT format('GRANT %I TO %I', :'owner_role', :'migrator_role') \gexec
SELECT format('GRANT pg_read_all_data TO %I', :'backup_role') \gexec

SELECT format('REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC', :'database_name') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I, %I', :'database_name', :'migrator_role', :'runtime_role') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'database_name', :'backup_role') \gexec
SELECT format('ALTER DATABASE %I OWNER TO %I', :'database_name', :'owner_role') \gexec

SELECT format('ALTER ROLE %I SET search_path TO public, pg_catalog', :'migrator_role') \gexec
SELECT format('ALTER ROLE %I SET lock_timeout TO %L', :'migrator_role', '5s') \gexec
SELECT format('ALTER ROLE %I SET idle_in_transaction_session_timeout TO %L', :'migrator_role', '30s') \gexec
SELECT format('ALTER ROLE %I SET search_path TO pg_catalog, public', :'runtime_role') \gexec
SELECT format('ALTER ROLE %I SET statement_timeout TO %L', :'runtime_role', '5s') \gexec
SELECT format('ALTER ROLE %I SET lock_timeout TO %L', :'runtime_role', '2s') \gexec
SELECT format('ALTER ROLE %I SET idle_in_transaction_session_timeout TO %L', :'runtime_role', '30s') \gexec
SELECT format('ALTER ROLE %I SET search_path TO pg_catalog, public', :'backup_role') \gexec
SELECT format('ALTER ROLE %I SET idle_in_transaction_session_timeout TO %L', :'backup_role', '30s') \gexec

\connect :database_name

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT format('ALTER SCHEMA public OWNER TO %I', :'owner_role') \gexec
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'migrator_role') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'runtime_role') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'backup_role') \gexec

-- Existing installations created application objects with the bootstrap
-- administrator before the dedicated owner/migrator split existed. Adopt only
-- non-extension objects in the application schema; never REASSIGN OWNED, which
-- would also change unrelated shared objects owned by the administrator.
SELECT format(
    'ALTER %s %I.%I OWNER TO %I',
    CASE c.relkind
        WHEN 'r' THEN 'TABLE'
        WHEN 'p' THEN 'TABLE'
        WHEN 'S' THEN 'SEQUENCE'
        WHEN 'v' THEN 'VIEW'
        WHEN 'm' THEN 'MATERIALIZED VIEW'
        WHEN 'f' THEN 'FOREIGN TABLE'
    END,
    n.nspname,
    c.relname,
    :'owner_role'
)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
  AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = :'admin_role')
  AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_class'::regclass
        AND d.objid = c.oid
        AND d.deptype = 'e'
  )
ORDER BY c.relkind, c.relname
\gexec

SELECT format(
    'ALTER %s %I.%I(%s) OWNER TO %I',
    CASE p.prokind
        WHEN 'p' THEN 'PROCEDURE'
        WHEN 'a' THEN 'AGGREGATE'
        ELSE 'FUNCTION'
    END,
    n.nspname,
    p.proname,
    pg_get_function_identity_arguments(p.oid),
    :'owner_role'
)
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = :'admin_role')
  AND NOT EXISTS (
      SELECT 1
      FROM pg_depend d
      WHERE d.classid = 'pg_proc'::regclass
        AND d.objid = p.oid
        AND d.deptype = 'e'
  )
ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)
\gexec

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
SELECT format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO %I', :'migrator_role') \gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', :'runtime_role') \gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'runtime_role') \gexec
SELECT format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO %I', :'runtime_role') \gexec

SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC', :'migrator_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC', :'migrator_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC', :'migrator_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', :'migrator_role', :'runtime_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I', :'migrator_role', :'runtime_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO %I', :'migrator_role', :'runtime_role') \gexec
