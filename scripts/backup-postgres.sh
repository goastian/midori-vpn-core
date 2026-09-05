#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

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
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_BACKUP_USER:?POSTGRES_BACKUP_USER is required}"
: "${POSTGRES_BACKUP_PASSWORD:?POSTGRES_BACKUP_PASSWORD is required}"
: "${BACKUP_DIR:?BACKUP_DIR is required}"

require_identifier POSTGRES_DB
require_identifier POSTGRES_BACKUP_USER
[[ -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] || die "BACKUP_DIR must be a real directory"
[[ "$(stat -c '%a' "$BACKUP_DIR")" == "700" ]] || die "BACKUP_DIR must have mode 0700"
podman container exists "$POSTGRES_CONTAINER" || die "PostgreSQL container does not exist"
[[ "$(podman inspect --format '{{.State.Running}}' "$POSTGRES_CONTAINER")" == true ]] || die "PostgreSQL container is not running"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
final_file="${BACKUP_DIR}/midorivpn-${timestamp}.dump"
manifest_file="${final_file}.sha256"
[[ ! -e "$final_file" && ! -e "$manifest_file" ]] || die "backup output already exists"
temporary_file="$(mktemp "${BACKUP_DIR}/.midorivpn-${timestamp}.XXXXXX.dump")"

cleanup() {
  rm -f -- "$temporary_file"
}
trap cleanup EXIT INT TERM

podman exec \
  -e PGPASSWORD="$POSTGRES_BACKUP_PASSWORD" \
  "$POSTGRES_CONTAINER" pg_dump \
    --username "$POSTGRES_BACKUP_USER" --dbname "$POSTGRES_DB" \
    --format custom --compress=6 --no-owner --no-privileges \
    >"$temporary_file"

[[ -s "$temporary_file" ]] || die "PostgreSQL backup is empty"
chmod 0600 "$temporary_file"
podman exec -i "$POSTGRES_CONTAINER" pg_restore --list \
  <"$temporary_file" >/dev/null || die "PostgreSQL custom-format validation failed"
mv -- "$temporary_file" "$final_file"
(
  cd -- "$BACKUP_DIR"
  sha256sum "$(basename -- "$final_file")" >"$(basename -- "$manifest_file")"
)
chmod 0600 "$final_file" "$manifest_file"

printf 'PostgreSQL backup created: %s\n' "$final_file"
printf 'Checksum manifest created: %s\n' "$manifest_file"
