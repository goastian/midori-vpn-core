#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

backup_dir=""
target_dir=""
scope="rootless"
restart_units=false

usage() {
  printf 'usage: %s --backup-dir PATH --target-dir PATH [--scope rootless|rootful] [--restart]\n' "$0"
}

while (($#)); do
  case "$1" in
    --backup-dir) backup_dir="${2:-}"; shift 2 ;;
    --target-dir) target_dir="${2:-}"; shift 2 ;;
    --scope) scope="${2:-}"; shift 2 ;;
    --restart) restart_units=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ -n "${backup_dir}" && -n "${target_dir}" ]] || { usage >&2; host_die "--backup-dir and --target-dir are required"; }
[[ "${scope}" == rootless || "${scope}" == rootful ]] || host_die "invalid scope"
host_require_private_directory "${backup_dir}"
[[ "${target_dir}" == /* && "$(basename -- "${target_dir}")" == midorivpn ]] || host_die "target must be an absolute dedicated directory named midorivpn"
if [[ "${scope}" == rootless ]]; then
  [[ "$(id -u)" != 0 ]] || host_die "rootless rollback must run as the service user"
  systemctl_cmd=(systemctl --user)
else
  [[ "$(id -u)" == 0 ]] || host_die "rootful rollback requires sudo or root"
  systemctl_cmd=(systemctl)
fi

[[ -d "${backup_dir}/previous" || -f "${backup_dir}/PREVIOUSLY_ABSENT" ]] || host_die "backup has no restorable state"
if [[ -d "${backup_dir}/previous" ]] && find "${backup_dir}/previous" -type l -print -quit | grep -q .; then
  host_die "backup must not contain symlinks"
fi

parent_dir="$(dirname -- "${target_dir}")"
install -d -m 0700 -- "${parent_dir}"
failed_copy="${parent_dir}/.midorivpn-failed.$(host_timestamp)"
if [[ -d "${target_dir}" ]]; then
  mv -- "${target_dir}" "${failed_copy}"
fi
if [[ -d "${backup_dir}/previous" ]]; then
  cp -a -- "${backup_dir}/previous" "${target_dir}"
fi
"${systemctl_cmd[@]}" daemon-reload

if [[ "${restart_units}" == true && -d "${target_dir}" ]]; then
  if [[ "${scope}" == rootless ]]; then
    if [[ -f "${target_dir}/midorivpn-control.container" ]]; then
      units=(midorivpn-control.service)
      [[ -f "${target_dir}/midorivpn-grafana.container" ]] && units+=(midorivpn-grafana.service)
    else
      units=(midorivpn-core.service)
    fi
  else
    units=()
    [[ -f "${target_dir}/midorivpn-openvpn.container" ]] && units+=(midorivpn-openvpn.service)
    [[ -f "${target_dir}/midorivpn-ikev2.container" ]] && units+=(midorivpn-ikev2.service)
  fi
  ((${#units[@]} == 0)) || "${systemctl_cmd[@]}" enable --now "${units[@]}"
fi

host_info "Unit configuration restored from ${backup_dir}"
host_info "Displaced configuration retained at ${failed_copy}"
host_info "Database and application data volumes were not restored or modified"
