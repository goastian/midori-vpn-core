#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

backup_dir="${1:-}"
[[ "$(id -u)" == 0 ]] || host_die "firewall rollback requires sudo or root"
host_require_private_directory "${backup_dir}"
host_require_regular_file "${backup_dir}/declared-rules.txt"
host_require_regular_file "${backup_dir}/added-rules.tsv"
host_require_command firewall-cmd
zone="$(sed -n 's/^zone=//p' "${backup_dir}/declared-rules.txt")"
[[ "${zone}" =~ ^[A-Za-z0-9_-]+$ ]] || host_die "invalid recorded firewall zone"
while IFS=$'\t' read -r kind value extra; do
  [[ -z "${extra:-}" && -n "${value}" ]] || host_die "invalid firewall rollback record"
  case "${kind}" in
    service) firewall-cmd --permanent --zone="${zone}" --remove-service="${value}" >/dev/null ;;
    port) firewall-cmd --permanent --zone="${zone}" --remove-port="${value}" >/dev/null ;;
    forward) firewall-cmd --permanent --zone="${zone}" --remove-forward-port="${value}" >/dev/null ;;
    *) host_die "invalid firewall rollback kind" ;;
  esac
done < "${backup_dir}/added-rules.tsv"
firewall-cmd --reload
host_info "firewalld rules added by the failed deployment were removed"
