# PostgreSQL 18 operations

MidoriVPN 2.0 uses PostgreSQL 18 as the only Control datastore. The standard
principal profile keeps PostgreSQL and PgBouncer inside one private Podman pod;
neither port is published on the host. PostgreSQL 18.6 and PgBouncer 1.25.2 are
the supported patch releases as of 2026-09-04.

## Security boundary

- Place `midori-pgdata-v18` on a host filesystem encrypted at rest. Verify the
  actual volume mount with `podman volume inspect` and the host block/filesystem
  encryption before setting `POSTGRES_DATA_AT_REST_ENCRYPTED=true`.
- The standard same-pod loopback paths may use `sslmode=disable`; they do not
  cross a network boundary. Any separate network namespace or host must use
  PostgreSQL TLS with `sslmode=verify-full`, a trusted CA and a hostname that
  matches the server certificate.
- Initialize host and local authentication with SCRAM-SHA-256. DB-02 rejects
  active `pg_hba.conf` rules that use another authentication method.
- Never expose 5432 or 6432 publicly. Permit an external database only through
  a private routed firewall policy restricted to the exact application nodes.

## Roles and startup order

The owner is `NOLOGIN`. The migrator, runtime and backup roles are distinct
`LOGIN` roles without superuser, database creation, role creation or replication
attributes. A separate PgBouncer identity alone can access its console.

`scripts/deploy-pod.sh` follows this order:

1. Start PostgreSQL with SCRAM and `pg_stat_statements` preloaded.
2. Apply `deploy/postgres/configure-roles.sql` as the bootstrap administrator.
3. Validate roles, ACLs, extension and `pg_hba.conf` with
   `deploy/postgres/check-policy.sql`.
4. Run `/usr/local/bin/midorivpn-migrate` once, directly against port 5432.
5. Reapply grants for databases that predate the default-privilege policy.
6. Start PgBouncer, then start Core with only the runtime credentials.

Do not start a new Core build before its one-shot migrator has completed. Core
intentionally no longer performs DDL during application startup.

## Runtime limits and pooling

The runtime role is fixed to `statement_timeout=5s`, `lock_timeout=2s`,
`idle_in_transaction_session_timeout=30s` and
`search_path=pg_catalog,public`. Core validates these values on every new
physical connection and fails closed in production if they drift.

The checked-in initial envelope is:

| Layer | Normal | Reserve/idle | Ceiling |
| --- | ---: | ---: | ---: |
| Core pool | 16 | 2 minimum idle | 16 |
| PgBouncer per database | 16 | 4 reserve | 24 backends |
| PgBouncer clients | — | — | 200 |

PgBouncer stays in transaction mode with protocol-level prepared-statement
tracking. Increase these values only after measuring acquisition waits,
PostgreSQL memory and concurrent workload. Keep the aggregate backend ceiling
below `max_connections` after reserving administrator and maintenance slots.

## Backup and isolated restore

Use a dedicated offline OpenPGP recovery key; never reuse a package-signing or
Control signing identity. Its public key is sufficient on the database host.
Keep the private key offline except during a restore drill.

With a running principal database, execute:

```text
POSTGRES_CONTAINER=midori-postgres \
POSTGRES_DB=<database> \
POSTGRES_BACKUP_USER=<backup-role> \
POSTGRES_BACKUP_PASSWORD=<secret> \
BACKUP_DIR=<absolute-0700-directory> \
BACKUP_GPG_RECIPIENT=<exact-40-hex-fingerprint> \
bash scripts/backup-postgres.sh
```

The custom-format dump streams directly into GPG; plaintext is never written
to disk. Store the `.dump.gpg` file and its `.sha256` companion on separate,
encrypted and access-controlled media.

Restore only into a new isolated database first:

```text
POSTGRES_CONTAINER=midori-postgres \
POSTGRES_ADMIN_USER=<bootstrap-admin> \
POSTGRES_ADMIN_PASSWORD=<secret> \
POSTGRES_OWNER_ROLE=<no-login-owner> \
RESTORE_DATABASE=midorivpn_restore_<unique-suffix> \
BACKUP_FILE=<absolute-dump.gpg-path> \
bash scripts/restore-postgres-backup.sh
```

After restore, compare migration version, row counts for critical tables and
application smoke results. Drop the isolated database only after evidence is
recorded. Losing either the backup private key or
`CONTROL_DATA_ENCRYPTION_KEY` makes recovery incomplete; back them up through
independent channels.

## Observability and query plans

The private mTLS exporter exposes only aggregate database and pool values:
availability, size, deadlocks, waiting locks, dead tuples, last autovacuum,
pool utilization/acquisition counters and aggregate `pg_stat_statements`
calls/runtime. It never selects or exports query text.

Run `EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS)` only on a restored staging copy
with representative cardinality. Record the plan and PostgreSQL settings in
private `.projects` evidence. Do not run `ANALYZE` plans for mutating statements
against production. Migration 22 provides a complete leading index for every
referencing-side foreign key, including historical rows omitted by hot-path
partial indexes.

## Rollback and incident handling

- Before a schema or runtime change, produce a new encrypted backup and prove
  its restore.
- A failed migration blocks Core startup. Do not force the migration table or
  mark a dirty version clean without inspecting the exact failed statement.
- If the new Core cannot connect, validate runtime role settings through a
  direct administrative session, then PgBouncer health and pool exhaustion.
- Existing tunnels may continue without Control, but new provisioning and
  cleanup must remain unavailable rather than bypassing PostgreSQL.
- WAL archiving/PITR is intentionally deferred until the planned replica is
  enabled; custom-format backup and restore remain mandatory in 2.0.0.
