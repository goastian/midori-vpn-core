#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
env_file="${1:-}"
backup_dir="${2:-}"
# shellcheck source=deploy/host/lib/common.sh
source "${ROOT_DIR}/deploy/host/lib/common.sh"

[[ "$(id -u)" != 0 ]] || host_die "database backup gate must run as the rootless service user"
[[ -n "${env_file}" ]] || host_die "environment file is required"
declare -A cfg=()
host_load_env "${env_file}" cfg
for key in POSTGRES_DB POSTGRES_BACKUP_USER POSTGRES_BACKUP_PASSWORD POSTGRES_ADMIN_USER POSTGRES_ADMIN_PASSWORD POSTGRES_OWNER_ROLE; do
  host_require_env cfg "${key}"
done
backup_dir="${backup_dir:-${cfg[POSTGRES_BACKUP_DIR]:-}}"
[[ "${backup_dir}" == /* ]] || host_die "backup directory must be absolute"
install -d -m 0700 -- "${backup_dir}"
host_require_private_directory "${backup_dir}"

export POSTGRES_CONTAINER=midorivpn-postgres
export POSTGRES_DB="${cfg[POSTGRES_DB]}"
export POSTGRES_BACKUP_USER="${cfg[POSTGRES_BACKUP_USER]}"
export POSTGRES_BACKUP_PASSWORD="${cfg[POSTGRES_BACKUP_PASSWORD]}"
export BACKUP_DIR="${backup_dir}"
bash "${ROOT_DIR}/scripts/backup-postgres.sh" >/dev/null
mapfile -t backups < <(find "${backup_dir}" -maxdepth 1 -type f -name 'midorivpn-*.dump' -printf '%T@ %p\n' | sort -nr | cut -d' ' -f2-)
((${#backups[@]} > 0)) || host_die "backup gate produced no dump"
backup_file="${backups[0]}"
restore_database="midorivpn_restore_$(date -u +%Y%m%d%H%M%S)_$$"

export POSTGRES_ADMIN_USER="${cfg[POSTGRES_ADMIN_USER]}"
export POSTGRES_ADMIN_PASSWORD="${cfg[POSTGRES_ADMIN_PASSWORD]}"
export POSTGRES_OWNER_ROLE="${cfg[POSTGRES_OWNER_ROLE]}"
export RESTORE_DATABASE="${restore_database}"
export BACKUP_FILE="${backup_file}"
created=false
admin_password_file="$(mktemp "${TMPDIR:-/tmp}/midorivpn-db-gate-password.XXXXXX")"
printf 'PGPASSWORD=%s\n' "${POSTGRES_ADMIN_PASSWORD}" > "${admin_password_file}"
chmod 0600 "${admin_password_file}"
cleanup_restore() {
  if [[ "${created}" == true ]]; then
    podman exec --env-file "${admin_password_file}" "${POSTGRES_CONTAINER}" \
      dropdb --if-exists --force -U "${POSTGRES_ADMIN_USER}" "${RESTORE_DATABASE}" >/dev/null 2>&1 || true
  fi
  rm -f -- "${admin_password_file}"
}
trap cleanup_restore EXIT
bash "${ROOT_DIR}/scripts/restore-postgres-backup.sh" >/dev/null
created=true
podman exec --env-file "${admin_password_file}" "${POSTGRES_CONTAINER}" \
  dropdb --if-exists --force -U "${POSTGRES_ADMIN_USER}" "${RESTORE_DATABASE}" >/dev/null
created=false
rm -f -- "${admin_password_file}"
trap - EXIT
unset POSTGRES_BACKUP_PASSWORD POSTGRES_ADMIN_PASSWORD
printf 'PostgreSQL backup and isolated restore gate passed: %s\n' "${backup_file}"
