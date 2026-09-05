#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

env_file=""
values_file=""
allowlist_file="${SCRIPT_DIR}/managed-env-keys.txt"
backup_dir=""
backup_record=""

usage() {
  printf 'usage: %s --env-file PATH --values-file PATH [--allowlist PATH] [--backup-dir PATH] [--backup-record FILE]\n' "$0"
}

while (($#)); do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --values-file) values_file="${2:-}"; shift 2 ;;
    --allowlist) allowlist_file="${2:-}"; shift 2 ;;
    --backup-dir) backup_dir="${2:-}"; shift 2 ;;
    --backup-record) backup_record="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ -n "${env_file}" && -n "${values_file}" ]] || { usage >&2; host_die "--env-file and --values-file are required"; }
host_require_regular_file "${values_file}"
host_require_regular_file "${allowlist_file}"

declare -A allowed=()
declare -A replacements=()
declare -A emitted=()
replacement_order=()
while IFS= read -r key || [[ -n "${key}" ]]; do
  [[ -z "${key}" || "${key}" =~ ^[[:space:]]*# ]] && continue
  host_validate_key "${key}"
  [[ ! -v "allowed[${key}]" ]] || host_die "duplicate key in allowlist: ${key}"
  allowed["${key}"]=1
done < "${allowlist_file}"

host_load_env "${values_file}" replacements
((${#replacements[@]} > 0)) || host_die "values file contains no managed values"
while IFS= read -r line || [[ -n "${line}" ]]; do
  [[ -z "${line}" || "${line}" =~ ^[[:space:]]*# ]] && continue
  replacement_order+=("${line%%=*}")
done < "${values_file}"
for key in "${replacement_order[@]}"; do
  [[ -v "allowed[${key}]" ]] || host_die "key is not managed and will not be changed: ${key}"
done

env_dir="$(dirname -- "${env_file}")"
install -d -m 0700 -- "${env_dir}"
temporary_file="$(mktemp "${env_dir}/.$(basename -- "${env_file}").XXXXXX")"
cleanup() { rm -f -- "${temporary_file}"; }
trap cleanup EXIT
chmod 0600 "${temporary_file}"

if [[ -e "${env_file}" ]]; then
  host_require_regular_file "${env_file}"
  backup_dir="${backup_dir:-${env_dir}/backups}"
  install -d -m 0700 -- "${backup_dir}"
  backup_file="${backup_dir}/$(basename -- "${env_file}").$(host_timestamp).bak"
  [[ ! -e "${backup_file}" ]] || host_die "backup already exists: ${backup_file}"
  install -m 0600 -- "${env_file}" "${backup_file}"

  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${line}" =~ ^([A-Z][A-Z0-9_]*)= ]]; then
      key="${BASH_REMATCH[1]}"
      if [[ -v "replacements[${key}]" ]]; then
        [[ ! -v "emitted[${key}]" ]] || host_die "duplicate key in target environment: ${key}"
        printf '%s=%s\n' "${key}" "${replacements[${key}]}" >> "${temporary_file}"
        emitted["${key}"]=1
        continue
      fi
    fi
    printf '%s\n' "${line}" >> "${temporary_file}"
  done < "${env_file}"
else
  backup_file=""
fi

if [[ -n "${backup_record}" ]]; then
  [[ "${backup_record}" == /* ]] || host_die "--backup-record must be absolute"
  install -d -m 0700 -- "$(dirname -- "${backup_record}")"
  printf '%s\n' "${backup_file:-ABSENT}" > "${backup_record}"
  chmod 0600 "${backup_record}"
fi

for key in "${replacement_order[@]}"; do
  if [[ ! -v "emitted[${key}]" ]]; then
    printf '%s=%s\n' "${key}" "${replacements[${key}]}" >> "${temporary_file}"
  fi
done

sync -f "${temporary_file}"
mv -f -- "${temporary_file}" "${env_file}"
trap - EXIT
chmod 0600 "${env_file}"
host_info "Environment updated atomically: ${env_file}"
if [[ -n "${backup_file}" ]]; then
  host_info "Previous environment backed up: ${backup_file}"
fi
