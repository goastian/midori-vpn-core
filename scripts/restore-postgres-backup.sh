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
command -v gpg >/dev/null 2>&1 || die "gpg is required"
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
[[ -f "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] || die "BACKUP_FILE must be a regular encrypted file"
[[ -f "${BACKUP_FILE}.sha256" && ! -L "${BACKUP_FILE}.sha256" ]] || die "backup checksum manifest is missing"
sha256sum --check "${BACKUP_FILE}.sha256" >/dev/null

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

gpg --batch --quiet --decrypt "$BACKUP_FILE" \
  | podman exec -i -e PGPASSWORD="$POSTGRES_ADMIN_PASSWORD" "$POSTGRES_CONTAINER" \
      pg_restore -U "$POSTGRES_ADMIN_USER" -d "$RESTORE_DATABASE" \
        --exit-on-error --no-owner --no-privileges

restore_created=false
printf 'Encrypted backup restored into isolated database: %s\n' "$RESTORE_DATABASE"
