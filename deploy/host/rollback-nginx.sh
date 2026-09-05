#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

backup_dir="${1:-}"
[[ "$(id -u)" == 0 ]] || host_die "Nginx rollback requires sudo or root"
host_require_private_directory "${backup_dir}"
host_require_regular_file "${backup_dir}/targets.tsv"
host_require_command nginx
host_require_command systemctl

while IFS=$'\t' read -r destination state source_name extra; do
  [[ -z "${extra:-}" && "${destination}" == /etc/nginx/* ]] || host_die "invalid Nginx rollback manifest"
  [[ ! -L "${destination}" ]] || host_die "refusing to restore through a symlink: ${destination}"
  case "${state}" in
    present)
      [[ "${source_name}" =~ ^[0-9]+\.conf$ ]] || host_die "invalid Nginx backup filename"
      host_require_regular_file "${backup_dir}/${source_name}"
      install -m 0644 -- "${backup_dir}/${source_name}" "${destination}"
      ;;
    absent)
      [[ "${source_name}" =~ ^[0-9]+\.absent$ ]] || host_die "invalid absent marker"
      host_require_regular_file "${backup_dir}/${source_name}"
      rm -f -- "${destination}"
      ;;
    *) host_die "invalid Nginx rollback state" ;;
  esac
done < "${backup_dir}/targets.tsv"
nginx -t
systemctl reload nginx.service
host_info "Nginx configuration restored from ${backup_dir}"
