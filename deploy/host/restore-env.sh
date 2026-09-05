#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

env_file=""
backup_file=""

usage() {
  printf 'usage: %s --env-file PATH --backup-file PATH\n' "$0"
}

while (($#)); do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --backup-file) backup_file="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ -n "${env_file}" && -n "${backup_file}" ]] || { usage >&2; host_die "--env-file and --backup-file are required"; }
host_require_regular_file "${backup_file}"
[[ "$(stat -c '%a' -- "${backup_file}")" == 600 ]] || host_die "environment backup must have mode 0600"
env_dir="$(dirname -- "${env_file}")"
install -d -m 0700 -- "${env_dir}"
[[ ! -L "${env_file}" ]] || host_die "refusing to replace a symlink"

if [[ -f "${env_file}" ]]; then
  displaced="${env_dir}/$(basename -- "${env_file}").pre-restore.$(host_timestamp).$$"
  install -m 0600 -- "${env_file}" "${displaced}"
else
  displaced=""
fi
temporary_file="$(mktemp "${env_dir}/.$(basename -- "${env_file}").XXXXXX")"
cleanup() { rm -f -- "${temporary_file}"; }
trap cleanup EXIT
install -m 0600 -- "${backup_file}" "${temporary_file}"
sync -f "${temporary_file}"
mv -f -- "${temporary_file}" "${env_file}"
trap - EXIT
host_info "Environment restored atomically: ${env_file}"
[[ -z "${displaced}" ]] || host_info "Displaced environment retained: ${displaced}"
