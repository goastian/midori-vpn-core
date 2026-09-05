#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_identifier() {
  local name="$1" value="${!1:-}"
  [[ "$value" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] || die "$name must be a simple PostgreSQL identifier"
}

command -v podman >/dev/null 2>&1 || die "podman is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
: "${POSTGRES_CONTAINER:?POSTGRES_CONTAINER is required}"
: "${POSTGRES_ADMIN_USER:?POSTGRES_ADMIN_USER is required}"
: "${POSTGRES_ADMIN_PASSWORD:?POSTGRES_ADMIN_PASSWORD is required}"
: "${POSTGRES_OWNER_ROLE:?POSTGRES_OWNER_ROLE is required}"
: "${RESTORE_DATABASE:?RESTORE_DATABASE is required}"
: "${BACKUP_FILE:?BACKUP_FILE is required}"

require_identifier POSTGRES_ADMIN_USER
require_identifier POSTGRES_OWNER_ROLE
require_identifier RESTORE_DATABASE
[[ "$RESTORE_DATABASE" == midorivpn_restore_* ]] || die "RESTORE_DATABASE must use the isolated midorivpn_restore_ prefix"
[[ -f "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] || die "BACKUP_FILE must be a regular file"
[[ -f "${BACKUP_FILE}.sha256" && ! -L "${BACKUP_FILE}.sha256" ]] || die "backup checksum manifest is missing"
[[ "$(stat -c '%a' "$BACKUP_FILE")" == 600 ]] || die "BACKUP_FILE must have mode 0600"
[[ "$(stat -c '%a' "${BACKUP_FILE}.sha256")" == 600 ]] || die "backup checksum manifest must have mode 0600"
backup_name="$(basename -- "$BACKUP_FILE")"
mapfile -t checksum_lines <"${BACKUP_FILE}.sha256"
[[ "${#checksum_lines[@]}" -eq 1 ]] || die "backup checksum manifest must contain exactly one entry"
read -r expected_hash expected_name extra <<<"${checksum_lines[0]}"
[[ "$expected_hash" =~ ^[0-9a-f]{64}$ && -z "${extra:-}" ]] || die "backup checksum manifest is malformed"
[[ "$expected_name" == "$backup_name" ]] || die "backup checksum manifest does not name BACKUP_FILE"
actual_hash="$(sha256sum "$BACKUP_FILE")"
actual_hash="${actual_hash%% *}"
[[ "$actual_hash" == "$expected_hash" ]] || die "backup checksum validation failed"
podman exec -i "$POSTGRES_CONTAINER" pg_restore --list \
  <"$BACKUP_FILE" >/dev/null || die "PostgreSQL custom-format validation failed"

if podman exec -e PGPASSWORD="$POSTGRES_ADMIN_PASSWORD" "$POSTGRES_CONTAINER" \
  psql -U "$POSTGRES_ADMIN_USER" -d postgres -Atc \
    "SELECT 1 FROM pg_database WHERE datname = '$RESTORE_DATABASE'" | grep -qx 1; then
  die "restore database already exists"
fi

restore_created=false
cleanup() {
  if [[ "$restore_created" == true ]]; then
    podman exec -e PGPASSWORD="$POSTGRES_ADMIN_PASSWORD" "$POSTGRES_CONTAINER" \
      dropdb --if-exists --force -U "$POSTGRES_ADMIN_USER" "$RESTORE_DATABASE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

podman exec -e PGPASSWORD="$POSTGRES_ADMIN_PASSWORD" "$POSTGRES_CONTAINER" \
  createdb -U "$POSTGRES_ADMIN_USER" --owner "$POSTGRES_OWNER_ROLE" "$RESTORE_DATABASE"
restore_created=true

podman exec -i -e PGPASSWORD="$POSTGRES_ADMIN_PASSWORD" "$POSTGRES_CONTAINER" \
  pg_restore -U "$POSTGRES_ADMIN_USER" -d "$RESTORE_DATABASE" \
    --exit-on-error --no-owner --no-privileges <"$BACKUP_FILE"

restore_created=false
printf 'Backup restored into isolated database: %s\n' "$RESTORE_DATABASE"
