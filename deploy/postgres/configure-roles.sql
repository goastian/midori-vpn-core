\set ON_ERROR_STOP on

\getenv database_name POSTGRES_DB
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

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', :'runtime_role') \gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'runtime_role') \gexec
SELECT format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO %I', :'runtime_role') \gexec

SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC', :'migrator_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC', :'migrator_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC', :'migrator_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', :'migrator_role', :'runtime_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I', :'migrator_role', :'runtime_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO %I', :'migrator_role', :'runtime_role') \gexec
