#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

command -v podman >/dev/null 2>&1 || die "podman is required"
: "${PGBOUNCER_IMAGE:?PGBOUNCER_IMAGE is required}"
: "${POSTGRES_IMAGE:?POSTGRES_IMAGE is required}"
: "${CORE_IMAGE:?CORE_IMAGE is required}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
role_policy="${script_dir}/../deploy/postgres/configure-roles.sql"
policy_check="${script_dir}/../deploy/postgres/check-policy.sql"
[[ -f "$role_policy" ]] || die "PostgreSQL role policy is missing"
[[ -f "$policy_check" ]] || die "PostgreSQL policy check is missing"

suffix="$$"
network="midorivpn-pgbouncer-test-${suffix}"
postgres_container="midorivpn-pgbouncer-postgres-${suffix}"
pooler_container="midorivpn-pgbouncer-${suffix}"
admin_user="midori_admin"
owner_role="midori_owner"
migrator_user="midori_migrator"
runtime_user="midori_runtime"
backup_user="midori_backup"
pooler_admin_user="midori_pooler_admin"
database_name="midori_vpn"
admin_password="midorivpn-admin-${suffix}"
migrator_password="midorivpn-migrator-${suffix}"
runtime_password="midorivpn-runtime-${suffix}"
backup_password="midorivpn-backup-${suffix}"
pooler_admin_password="midorivpn-pooler-${suffix}"
work_dir="$(mktemp -d /tmp/midorivpn-db02-test.XXXXXX)"
chmod 0700 "$work_dir"
load_pid=""
lock_pid=""

cleanup() {
  [[ -z "$load_pid" ]] || kill "$load_pid" >/dev/null 2>&1 || true
  [[ -z "$lock_pid" ]] || kill "$lock_pid" >/dev/null 2>&1 || true
  podman rm -f "$pooler_container" "$postgres_container" >/dev/null 2>&1 || true
  podman network rm "$network" >/dev/null 2>&1 || true
  rm -rf -- "$work_dir"
}
trap cleanup EXIT INT TERM

wait_for_command() {
  local container="$1"
  shift
  for _ in {1..40}; do
    if podman exec "$container" "$@" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(podman inspect --format '{{.State.Running}}' "$container")" != true ]]; then
      podman logs "$container" >&2
      return 1
    fi
    sleep 1
  done
  podman logs "$container" >&2
  return 1
}

podman network create "$network" >/dev/null
podman run -d --name "$postgres_container" --network "$network" \
  -e POSTGRES_USER="$admin_user" \
  -e POSTGRES_PASSWORD="$admin_password" \
  -e POSTGRES_DB="$database_name" \
  -e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256 --auth-local=scram-sha-256" \
  -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  "$POSTGRES_IMAGE" postgres \
    -c shared_preload_libraries=pg_stat_statements \
    -c password_encryption=scram-sha-256 >/dev/null
wait_for_command "$postgres_container" pg_isready -U "$admin_user" -d "$database_name"
postgres_ip="$(podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$postgres_container")"
[[ "$postgres_ip" =~ ^[0-9a-fA-F:.]+$ ]] || die "PostgreSQL container has no private address"

podman exec -i \
  -e PGPASSWORD="$admin_password" \
  -e POSTGRES_DB="$database_name" \
  -e POSTGRES_OWNER_ROLE="$owner_role" \
  -e POSTGRES_MIGRATOR_USER="$migrator_user" \
  -e POSTGRES_MIGRATOR_PASSWORD="$migrator_password" \
  -e POSTGRES_RUNTIME_USER="$runtime_user" \
  -e POSTGRES_RUNTIME_PASSWORD="$runtime_password" \
  -e POSTGRES_BACKUP_USER="$backup_user" \
  -e POSTGRES_BACKUP_PASSWORD="$backup_password" \
  "$postgres_container" psql -U "$admin_user" -d postgres --no-psqlrc -v ON_ERROR_STOP=1 < "$role_policy"

podman exec -i \
  -e PGPASSWORD="$admin_password" \
  -e POSTGRES_DB="$database_name" \
  -e POSTGRES_OWNER_ROLE="$owner_role" \
  -e POSTGRES_MIGRATOR_USER="$migrator_user" \
  -e POSTGRES_RUNTIME_USER="$runtime_user" \
  -e POSTGRES_BACKUP_USER="$backup_user" \
  "$postgres_container" psql -U "$admin_user" -d "$database_name" --no-psqlrc -v ON_ERROR_STOP=1 < "$policy_check"

podman run --rm --network "$network" \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --entrypoint /usr/local/bin/midorivpn-migrate \
  -e POSTGRES_MIGRATOR_USER="$migrator_user" \
  -e POSTGRES_MIGRATOR_PASSWORD="$migrator_password" \
  -e POSTGRES_MIGRATION_HOST="$postgres_ip" \
  -e POSTGRES_MIGRATION_PORT=5432 \
  -e POSTGRES_DB="$database_name" \
  -e POSTGRES_MIGRATION_SSLMODE=disable \
  "$CORE_IMAGE"

podman exec -i \
  -e PGPASSWORD="$admin_password" \
  -e POSTGRES_DB="$database_name" \
  -e POSTGRES_OWNER_ROLE="$owner_role" \
  -e POSTGRES_MIGRATOR_USER="$migrator_user" \
  -e POSTGRES_MIGRATOR_PASSWORD="$migrator_password" \
  -e POSTGRES_RUNTIME_USER="$runtime_user" \
  -e POSTGRES_RUNTIME_PASSWORD="$runtime_password" \
  -e POSTGRES_BACKUP_USER="$backup_user" \
  -e POSTGRES_BACKUP_PASSWORD="$backup_password" \
  "$postgres_container" psql -U "$admin_user" -d postgres --no-psqlrc -v ON_ERROR_STOP=1 < "$role_policy"

missing_fk_indexes="$(podman exec -e PGPASSWORD="$admin_password" "$postgres_container" \
  psql -U "$admin_user" -d "$database_name" --no-psqlrc -At -v ON_ERROR_STOP=1 -c "
    SELECT c.conrelid::regclass::text || '|' || c.conname
    FROM pg_constraint c
    WHERE c.contype = 'f'
      AND c.connamespace = 'public'::regnamespace
      AND NOT EXISTS (
        SELECT 1
        FROM pg_index i
        WHERE i.indrelid = c.conrelid
          AND i.indisvalid
          AND i.indisready
          AND i.indpred IS NULL
          AND (
            SELECT array_agg(key.attnum ORDER BY key.ordinality)
            FROM unnest(i.indkey) WITH ORDINALITY AS key(attnum, ordinality)
            WHERE key.ordinality <= cardinality(c.conkey)
          ) = c.conkey
      )
    ORDER BY c.conrelid::regclass::text, c.conname")"
if [[ -n "$missing_fk_indexes" ]]; then
  printf 'Foreign keys without a leading index:\n%s\n' "$missing_fk_indexes" >&2
  die "foreign-key index audit failed"
fi

podman run --rm --network "$network" \
  -e PGPASSWORD="$migrator_password" "$POSTGRES_IMAGE" \
  psql -h "$postgres_ip" -U "$migrator_user" -d "$database_name" \
  -v ON_ERROR_STOP=1 -c 'CREATE TABLE pgbouncer_probe (id bigint PRIMARY KEY); INSERT INTO pgbouncer_probe VALUES (1)' >/dev/null

backup_dir="$work_dir/backups"
install -d -m 0700 "$backup_dir"

env \
  POSTGRES_CONTAINER="$postgres_container" \
  POSTGRES_DB="$database_name" \
  POSTGRES_BACKUP_USER="$backup_user" \
  POSTGRES_BACKUP_PASSWORD="$backup_password" \
  BACKUP_DIR="$backup_dir" \
  bash "$script_dir/backup-postgres.sh" >/dev/null
backup_file="$(find "$backup_dir" -maxdepth 1 -type f -name '*.dump' -print -quit)"
[[ -n "$backup_file" ]] || die "backup artifact was not created"
[[ "$(stat -c '%a' "$backup_file")" == 600 ]] || die "backup artifact is not private"
[[ "$(stat -c '%a' "${backup_file}.sha256")" == 600 ]] || die "backup manifest is not private"
tampered_backup="$backup_dir/tampered.dump"
cp -- "$backup_file" "$tampered_backup"
printf 'tampered' >>"$tampered_backup"
chmod 0600 "$tampered_backup"
original_hash="$(sha256sum "$backup_file")"
original_hash="${original_hash%% *}"
printf '%s  %s\n' "$original_hash" "$(basename -- "$tampered_backup")" >"${tampered_backup}.sha256"
chmod 0600 "${tampered_backup}.sha256"
if env \
  POSTGRES_CONTAINER="$postgres_container" \
  POSTGRES_ADMIN_USER="$admin_user" \
  POSTGRES_ADMIN_PASSWORD="$admin_password" \
  POSTGRES_OWNER_ROLE="$owner_role" \
  RESTORE_DATABASE="midorivpn_restore_tampered_${suffix}" \
  BACKUP_FILE="$tampered_backup" \
  bash "$script_dir/restore-postgres-backup.sh" >/dev/null 2>&1; then
  die "restore accepted a backup whose SHA-256 did not match"
fi
rm -f -- "$tampered_backup" "${tampered_backup}.sha256"
restore_database="midorivpn_restore_${suffix}"
env \
  POSTGRES_CONTAINER="$postgres_container" \
  POSTGRES_ADMIN_USER="$admin_user" \
  POSTGRES_ADMIN_PASSWORD="$admin_password" \
  POSTGRES_OWNER_ROLE="$owner_role" \
  RESTORE_DATABASE="$restore_database" \
  BACKUP_FILE="$backup_file" \
  bash "$script_dir/restore-postgres-backup.sh" >/dev/null
restored_probe="$(podman exec -e PGPASSWORD="$admin_password" "$postgres_container" \
  psql -U "$admin_user" -d "$restore_database" -Atc 'SELECT count(*) FROM pgbouncer_probe')"
[[ "$restored_probe" == 1 ]] || die "backup restore did not preserve probe data"

podman run --rm --network "$network" \
  -e PGPASSWORD="$migrator_password" "$POSTGRES_IMAGE" \
  psql -h "$postgres_ip" -U "$migrator_user" -d "$database_name" -v ON_ERROR_STOP=1 -c "
    INSERT INTO users (id, authentik_uid, email, display_name)
    VALUES ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'db02-plan-user', 'plan@example.invalid', 'DB02 Plan');
    INSERT INTO vpn_servers (id, name, host, legacy_node_unbound)
    SELECT md5('server-' || value)::uuid, 'plan-' || value, 'plan-' || value || '.invalid', TRUE
    FROM generate_series(1, 100) value;
    INSERT INTO devices (id, user_id, client_instance_id, reported_name, device_type, first_seen_at, last_seen_at)
    SELECT md5('device-' || value)::uuid,
           'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
           md5('instance-' || value)::uuid,
           'plan-' || value, 'desktop',
           NOW() - make_interval(secs => value),
           NOW() - make_interval(secs => value)
    FROM generate_series(1, 10000) value;
    INSERT INTO peers (
      user_id, server_id, public_key, assigned_ip, is_active,
      device_name, device_id, created_at
    )
    SELECT 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
           md5('server-' || ((value % 100) + 1))::uuid,
           'plan-peer-' || value,
           '10.200.' || value || '/32', FALSE,
           'plan-' || ((value % 100) + 1),
           md5('device-' || ((value % 100) + 1))::uuid,
           NOW() - make_interval(secs => value)
    FROM generate_series(1, 20000) value;
    ANALYZE users;
    ANALYZE vpn_servers;
    ANALYZE devices;
    ANALYZE peers;
  " >/dev/null

podman run -d --name "$pooler_container" --network "$network" \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --tmpfs /run/pgbouncer:rw,noexec,nosuid,nodev,size=4m,mode=1733 \
  -e POSTGRES_HOST="$postgres_container" \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_RUNTIME_USER="$runtime_user" \
  -e POSTGRES_RUNTIME_PASSWORD="$runtime_password" \
  -e POSTGRES_DB="$database_name" \
  -e PGBOUNCER_ADMIN_USER="$pooler_admin_user" \
  -e PGBOUNCER_ADMIN_PASSWORD="$pooler_admin_password" \
  "$PGBOUNCER_IMAGE" >/dev/null
wait_for_command "$pooler_container" pg_isready -h 127.0.0.1 -p 6432 -U "$runtime_user" -d "$database_name"
pooler_ip="$(podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$pooler_container")"
[[ "$pooler_ip" =~ ^[0-9a-fA-F:.]+$ ]] || die "PgBouncer container has no private address"

query_result="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" \
  -v ON_ERROR_STOP=1 -Atc "SELECT current_database(), current_user, current_setting('statement_timeout'), current_setting('lock_timeout'), current_setting('idle_in_transaction_session_timeout'), current_setting('search_path'), (SELECT count(*) FROM pgbouncer_probe), (SELECT version FROM schema_migrations)")"
[[ "$query_result" == "${database_name}|${runtime_user}|5s|2s|30s|pg_catalog, public|1|22" ]] || die "runtime query, schema version or hardening settings did not traverse PgBouncer"

if podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" \
  -v ON_ERROR_STOP=1 -c 'CREATE TABLE runtime_must_not_create (id integer)' >/dev/null 2>&1; then
  die "runtime role unexpectedly executed DDL"
fi

if podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d pgbouncer \
  -v ON_ERROR_STOP=1 -c 'SHOW POOLS' >/dev/null 2>&1; then
  die "runtime role unexpectedly accessed the PgBouncer administration database"
fi

pooler_config="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$pooler_admin_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$pooler_admin_user" -d pgbouncer \
  -v ON_ERROR_STOP=1 -Atc 'SHOW CONFIG')"
grep -q '^auth_type|scram-sha-256|' <<<"$pooler_config" || die "SCRAM authentication is not active"
grep -q '^pool_mode|transaction|' <<<"$pooler_config" || die "transaction pooling is not active"
grep -q '^max_prepared_statements|100|' <<<"$pooler_config" || die "prepared statement tracking is not active"
grep -q '^max_client_conn|200|' <<<"$pooler_config" || die "client ceiling does not match the measured envelope"
grep -q '^default_pool_size|16|' <<<"$pooler_config" || die "default pool does not match the measured envelope"
grep -q '^max_db_connections|24|' <<<"$pooler_config" || die "database ceiling does not match the measured envelope"
podman top "$pooler_container" user comm | grep -Eq '^pgbouncer[[:space:]]+pgbouncer$' || die "PgBouncer is not running as its dedicated user"

device_list_plan="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" -At -v ON_ERROR_STOP=1 -c "
    EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS)
    SELECT id FROM devices
    WHERE user_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' AND revoked_at IS NULL
    ORDER BY last_seen_at DESC LIMIT 50")"
grep -q 'idx_devices_user_last_seen' <<<"$device_list_plan" || die "device list plan did not use its bounded ordering index"

device_sessions_plan="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" -At -v ON_ERROR_STOP=1 -c "
    EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS)
    SELECT id FROM peers
    WHERE user_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
      AND device_id = md5('device-1')::uuid
    ORDER BY created_at DESC, id DESC LIMIT 50")"
grep -q 'idx_peers_device_created' <<<"$device_sessions_plan" || die "device session plan did not use its history index"

recent_sessions_plan="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" -At -v ON_ERROR_STOP=1 -c "
    EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS)
    SELECT id FROM peers
    WHERE user_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    ORDER BY created_at DESC, id DESC LIMIT 10")"
grep -q 'idx_peers_user_created' <<<"$recent_sessions_plan" || die "recent session plan did not use its dashboard index"

server_history_plan="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" -At -v ON_ERROR_STOP=1 -c "
    EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS)
    SELECT id FROM peers
    WHERE server_id = md5('server-1')::uuid
    ORDER BY created_at DESC")"
grep -q 'idx_peers_server_fk' <<<"$server_history_plan" || die "server history plan did not use the full foreign-key index"
printf '%s\n%s\n%s\n%s\n' \
  "$device_list_plan" "$device_sessions_plan" "$recent_sessions_plan" "$server_history_plan" \
  > "$work_dir/query-plans.txt"

podman exec -e PGPASSWORD="$runtime_password" "$postgres_container" sh -ceu '
  pids=""
  i=1
  while [ "$i" -le 20 ]; do
    psql -h "$1" -p 6432 -U "$2" -d "$3" -v ON_ERROR_STOP=1 -c "SELECT pg_sleep(2)" >/dev/null &
    pids="$pids $!"
    i=$((i + 1))
  done
  for pid in $pids; do wait "$pid"; done
' sh "$pooler_ip" "$runtime_user" "$database_name" &
load_pid=$!
sleep 1
pool_row="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$pooler_admin_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$pooler_admin_user" -d pgbouncer \
  -v ON_ERROR_STOP=1 -Atc 'SHOW POOLS' | awk -F'|' -v db="$database_name" -v role="$runtime_user" '$1 == db && $2 == role {print; exit}')"
IFS='|' read -r _ _ pool_clients_active pool_clients_waiting _ _ pool_servers_active _ <<<"$pool_row"
[[ "$pool_clients_active" =~ ^[0-9]+$ && "$pool_clients_waiting" =~ ^[0-9]+$ && "$pool_servers_active" =~ ^[0-9]+$ ]] || die "PgBouncer load metrics were not numeric"
(( pool_clients_active + pool_clients_waiting >= 20 )) || die "concurrent client load did not reach the pool"
(( pool_clients_waiting >= 4 )) || die "bounded pool did not queue excess clients"
(( pool_servers_active <= 16 )) || die "normal backend pool exceeded its configured ceiling"
wait "$load_pid"
load_pid=""

if podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" \
  -v ON_ERROR_STOP=1 -c 'SELECT pg_sleep(6)' >/dev/null 2>&1; then
  die "runtime statement_timeout did not stop a six-second statement"
fi

podman exec -e PGPASSWORD="$migrator_password" "$postgres_container" \
  psql -U "$migrator_user" -d "$database_name" -v ON_ERROR_STOP=1 \
  -c 'BEGIN; LOCK TABLE pgbouncer_probe IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(4); COMMIT' >/dev/null &
lock_pid=$!
sleep 1
if podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" \
  -v ON_ERROR_STOP=1 -c 'SELECT count(*) FROM pgbouncer_probe' >/dev/null 2>&1; then
  die "runtime lock_timeout did not stop a blocked query"
fi
wait "$lock_pid"
lock_pid=""

podman stop "$postgres_container" >/dev/null
if podman run --rm --network "$network" \
  -e PGPASSWORD="$runtime_password" -e PGCONNECT_TIMEOUT=2 "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$runtime_user" -d "$database_name" \
  -v ON_ERROR_STOP=1 -c 'SELECT 1' >/dev/null 2>&1; then
  die "PgBouncer did not fail closed while PostgreSQL was offline"
fi
podman start "$postgres_container" >/dev/null
wait_for_command "$postgres_container" pg_isready -U "$admin_user" -d "$database_name"
# Positional parameters are expanded by the container-side shell.
# shellcheck disable=SC2016
wait_for_command "$pooler_container" sh -ceu \
  'PGPASSWORD="$1" psql -h 127.0.0.1 -p 6432 -U "$2" -d "$3" -v ON_ERROR_STOP=1 -c "SELECT 1" >/dev/null' \
  sh "$runtime_password" "$runtime_user" "$database_name"

printf 'PostgreSQL migration, private restore, bounded-pool, timeout, restart and PgBouncer validation passed.\n'
