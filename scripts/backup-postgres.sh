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
command -v gpg >/dev/null 2>&1 || die "gpg is required"
: "${POSTGRES_CONTAINER:?POSTGRES_CONTAINER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_BACKUP_USER:?POSTGRES_BACKUP_USER is required}"
: "${POSTGRES_BACKUP_PASSWORD:?POSTGRES_BACKUP_PASSWORD is required}"
: "${BACKUP_DIR:?BACKUP_DIR is required}"
: "${BACKUP_GPG_RECIPIENT:?BACKUP_GPG_RECIPIENT is required}"

require_identifier POSTGRES_DB
require_identifier POSTGRES_BACKUP_USER
[[ "$BACKUP_GPG_RECIPIENT" =~ ^[A-Fa-f0-9]{40}$ ]] || die "BACKUP_GPG_RECIPIENT must be an exact 40-hex fingerprint"
[[ -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]] || die "BACKUP_DIR must be a real directory"
[[ "$(stat -c '%a' "$BACKUP_DIR")" == "700" ]] || die "BACKUP_DIR must have mode 0700"
podman container exists "$POSTGRES_CONTAINER" || die "PostgreSQL container does not exist"
[[ "$(podman inspect --format '{{.State.Running}}' "$POSTGRES_CONTAINER")" == true ]] || die "PostgreSQL container is not running"
gpg --batch --list-keys "$BACKUP_GPG_RECIPIENT" >/dev/null 2>&1 || die "backup encryption recipient is unavailable"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
final_file="${BACKUP_DIR}/midorivpn-${timestamp}.dump.gpg"
manifest_file="${final_file}.sha256"
[[ ! -e "$final_file" && ! -e "$manifest_file" ]] || die "backup output already exists"
temporary_file="$(mktemp "${BACKUP_DIR}/.midorivpn-${timestamp}.XXXXXX.gpg")"

cleanup() {
  rm -f -- "$temporary_file"
}
trap cleanup EXIT

podman exec \
  -e PGPASSWORD="$POSTGRES_BACKUP_PASSWORD" \
  "$POSTGRES_CONTAINER" pg_dump \
    --username "$POSTGRES_BACKUP_USER" --dbname "$POSTGRES_DB" \
    --format custom --compress=6 --no-owner --no-privileges \
  | gpg --batch --yes --quiet --trust-model always \
      --recipient "$BACKUP_GPG_RECIPIENT" --output "$temporary_file" --encrypt

[[ -s "$temporary_file" ]] || die "encrypted backup is empty"
gpg --batch --list-packets "$temporary_file" >/dev/null 2>&1 || die "encrypted backup packet validation failed"
mv -- "$temporary_file" "$final_file"
sha256sum "$final_file" > "$manifest_file"
chmod 0600 "$final_file" "$manifest_file"

printf 'Encrypted PostgreSQL backup created: %s\n' "$final_file"
printf 'Checksum manifest created: %s\n' "$manifest_file"
