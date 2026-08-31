#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

command -v podman >/dev/null 2>&1 || die "podman is required"
: "${PGBOUNCER_IMAGE:?PGBOUNCER_IMAGE is required}"
: "${POSTGRES_IMAGE:?POSTGRES_IMAGE is required}"

suffix="$$"
network="midorivpn-pgbouncer-test-${suffix}"
postgres_container="midorivpn-pgbouncer-postgres-${suffix}"
pooler_container="midorivpn-pgbouncer-${suffix}"
database_user="midori"
database_name="midori_vpn"
database_password="midorivpn-pgbouncer-test-${suffix}"

cleanup() {
  podman rm -f "$pooler_container" "$postgres_container" >/dev/null 2>&1 || true
  podman network rm "$network" >/dev/null 2>&1 || true
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
  -e POSTGRES_USER="$database_user" \
  -e POSTGRES_PASSWORD="$database_password" \
  -e POSTGRES_DB="$database_name" \
  "$POSTGRES_IMAGE" >/dev/null
wait_for_command "$postgres_container" pg_isready -U "$database_user" -d "$database_name"
postgres_ip="$(podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$postgres_container")"
[[ "$postgres_ip" =~ ^[0-9a-fA-F:.]+$ ]] || die "PostgreSQL container has no private address"

podman run -d --name "$pooler_container" --network "$network" \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  --tmpfs /run/pgbouncer:rw,noexec,nosuid,nodev,size=4m,mode=1733 \
  -e POSTGRES_HOST="$postgres_ip" \
  -e POSTGRES_PORT=5432 \
  -e POSTGRES_USER="$database_user" \
  -e POSTGRES_PASSWORD="$database_password" \
  -e POSTGRES_DB="$database_name" \
  "$PGBOUNCER_IMAGE" >/dev/null
wait_for_command "$pooler_container" pg_isready -h 127.0.0.1 -p 6432 -U "$database_user" -d "$database_name"
pooler_ip="$(podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$pooler_container")"
[[ "$pooler_ip" =~ ^[0-9a-fA-F:.]+$ ]] || die "PgBouncer container has no private address"

query_result="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$database_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$database_user" -d "$database_name" \
  -v ON_ERROR_STOP=1 -Atc 'SELECT current_database(), current_user')"
[[ "$query_result" == "${database_name}|${database_user}" ]] || die "query did not traverse PgBouncer"

pooler_config="$(podman run --rm --network "$network" \
  -e PGPASSWORD="$database_password" "$POSTGRES_IMAGE" \
  psql -h "$pooler_ip" -p 6432 -U "$database_user" -d pgbouncer \
  -v ON_ERROR_STOP=1 -Atc 'SHOW CONFIG')"
grep -q '^auth_type|scram-sha-256|' <<<"$pooler_config" || die "SCRAM authentication is not active"
grep -q '^pool_mode|transaction|' <<<"$pooler_config" || die "transaction pooling is not active"
grep -q '^max_prepared_statements|100|' <<<"$pooler_config" || die "prepared statement tracking is not active"
podman top "$pooler_container" user comm | grep -Eq '^pgbouncer[[:space:]]+pgbouncer$' || die "PgBouncer is not running as its dedicated user"

printf 'PgBouncer SCRAM and transaction-pooling validation passed.\n'
