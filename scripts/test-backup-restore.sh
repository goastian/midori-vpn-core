#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

require_identifier() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || die "$name must be a PostgreSQL identifier"
}

command -v podman >/dev/null 2>&1 || die "podman is required"
: "${POSTGRES_CONTAINER:?POSTGRES_CONTAINER is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
require_identifier POSTGRES_USER "$POSTGRES_USER"
require_identifier POSTGRES_DB "$POSTGRES_DB"
[[ "$POSTGRES_DB" != "postgres" && "$POSTGRES_DB" != template* ]] || die "refusing to test a PostgreSQL maintenance database"

podman container exists "$POSTGRES_CONTAINER" || die "PostgreSQL container does not exist"
[[ "$(podman inspect --format '{{.State.Running}}' "$POSTGRES_CONTAINER")" == "true" ]] || die "PostgreSQL container is not running"

restore_db="midorivpn_restore_$(date -u +%Y%m%d_%H%M%S)_$$"
require_identifier restore_db "$restore_db"
work_dir="$(mktemp -d /tmp/midorivpn-backup-restore.XXXXXX)"
backup_file="$work_dir/database.dump"
restore_created=false

cleanup() {
  if [[ "$restore_created" == true ]]; then
    podman exec "$POSTGRES_CONTAINER" dropdb --if-exists --force --username "$POSTGRES_USER" "$restore_db" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT INT TERM

printf 'Creating a consistent custom-format backup...\n'
podman exec "$POSTGRES_CONTAINER" pg_dump \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --format custom --compress=6 --no-owner --no-privileges >"$backup_file"
[[ -s "$backup_file" ]] || die "pg_dump produced an empty backup"

printf 'Restoring into isolated database %s...\n' "$restore_db"
podman exec "$POSTGRES_CONTAINER" createdb --username "$POSTGRES_USER" "$restore_db"
restore_created=true
podman exec -i "$POSTGRES_CONTAINER" pg_restore \
  --username "$POSTGRES_USER" --dbname "$restore_db" \
  --exit-on-error --no-owner --no-privileges <"$backup_file"

for table_name in users peers schema_migrations; do
  require_identifier table_name "$table_name"
  source_count="$(podman exec "$POSTGRES_CONTAINER" psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --tuples-only --no-align --command "SELECT count(*) FROM $table_name")"
  restored_count="$(podman exec "$POSTGRES_CONTAINER" psql --username "$POSTGRES_USER" --dbname "$restore_db" --tuples-only --no-align --command "SELECT count(*) FROM $table_name")"
  [[ "$source_count" =~ ^[0-9]+$ && "$restored_count" =~ ^[0-9]+$ ]] || die "invalid row count for $table_name"
  [[ "$source_count" == "$restored_count" ]] || die "$table_name row count differs after restore"
  printf '%s: %s rows verified\n' "$table_name" "$restored_count"
done

printf 'Backup and isolated restore validation passed.\n'
