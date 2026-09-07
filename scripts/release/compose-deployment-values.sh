#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
variables_file=""
secrets_file=""
core_image=""
control_image=""
output_file=""
map_file="${ROOT_DIR}/deploy/ci/environment-map.json"
# shellcheck source=deploy/host/lib/common.sh
source "${ROOT_DIR}/deploy/host/lib/common.sh"

usage() {
  printf 'usage: %s --variables-file FILE --secrets-file FILE --core-image REF --control-image REF --output FILE [--map FILE]\n' "$0"
}
while (($#)); do
  case "$1" in
    --variables-file) variables_file="${2:-}"; shift 2 ;;
    --secrets-file) secrets_file="${2:-}"; shift 2 ;;
    --core-image) core_image="${2:-}"; shift 2 ;;
    --control-image) control_image="${2:-}"; shift 2 ;;
    --output) output_file="${2:-}"; shift 2 ;;
    --map) map_file="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done
[[ -n "${variables_file}" && -n "${secrets_file}" && -n "${output_file}" ]] || { usage >&2; host_die "missing required argument"; }
host_require_regular_file "${variables_file}"
host_require_regular_file "${secrets_file}"
host_require_regular_file "${map_file}"
host_validate_versioned_image "${core_image}" CORE_IMAGE
host_validate_versioned_image "${control_image}" CONTROL_IMAGE
bash "${ROOT_DIR}/scripts/release/validate-deployment-environment-map.sh" "${map_file}" "${ROOT_DIR}/deploy/host/managed-env-keys.txt" >/dev/null

declare -A variables=() secrets=() seen=()
host_load_env "${variables_file}" variables
host_load_env "${secrets_file}" secrets
for image_key in CORE_IMAGE CONTROL_IMAGE; do
  [[ ! -v "variables[${image_key}]" && ! -v "secrets[${image_key}]" ]] || host_die "${image_key} is supplied only by the verified release tag"
done

validate_class() {
  local collection_name="$1" expected="$2" key actual
  local -n collection="${collection_name}"
  for key in "${!collection[@]}"; do
    actual="$(jq -er --arg key "${key}" '.managed_env[$key] // empty' "${map_file}")" || host_die "unmanaged deployment key: ${key}"
    [[ "${actual}" == "${expected}" ]] || host_die "${key} must be supplied as an Actions ${actual}, not ${expected}"
    [[ ! -v "seen[${key}]" ]] || host_die "${key} is present in both Actions fragments"
    seen["${key}"]=1
  done
}
validate_class variables variable
validate_class secrets secret
profile="${variables[DEPLOYMENT_PROFILE]:-}"
[[ "${profile}" == principal || "${profile}" == core-node ]] || host_die "DEPLOYMENT_PROFILE must be supplied as an Actions variable"

output_dir="$(dirname -- "${output_file}")"
install -d -m 0700 -- "${output_dir}"
temporary="$(mktemp "${output_dir}/.$(basename -- "${output_file}").XXXXXX")"
cleanup() { rm -f -- "${temporary}"; }
trap cleanup EXIT
chmod 0600 "${temporary}"
{
  for key in "${!variables[@]}"; do printf '%s=%s\n' "${key}" "${variables[${key}]}"; done
  for key in "${!secrets[@]}"; do printf '%s=%s\n' "${key}" "${secrets[${key}]}"; done
  printf 'CORE_IMAGE=%s\n' "${core_image}"
  if [[ "${profile}" == principal ]]; then
    printf 'CONTROL_IMAGE=%s\n' "${control_image}"
  fi
} | sort > "${temporary}"
mv -f -- "${temporary}" "${output_file}"
trap - EXIT
chmod 0600 "${output_file}"
image_count=1
[[ "${profile}" != principal ]] || image_count=2
printf 'Composed %s allowlisted %s deployment values without replacing the target environment.\n' \
  "$((${#variables[@]} + ${#secrets[@]} + image_count))" "${profile}"
