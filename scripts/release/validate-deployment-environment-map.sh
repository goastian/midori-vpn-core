#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
map_file="${1:-${ROOT_DIR}/deploy/ci/environment-map.json}"
managed_file="${2:-${ROOT_DIR}/deploy/host/managed-env-keys.txt}"

for command_name in jq comm sort; do
  command -v "${command_name}" >/dev/null || { printf 'error: %s is required\n' "${command_name}" >&2; exit 1; }
done

tmp="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-env-map.XXXXXX")"
cleanup() { rm -rf -- "${tmp}"; }
trap cleanup EXIT
sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' "${managed_file}" | sort > "${tmp}/managed"
jq -er '
  select(.schema_version == 1) |
  .managed_env | to_entries[] |
  select(.value == "variable" or .value == "secret") | .key
' "${map_file}" | sort > "${tmp}/mapped"
jq --stream -er '
  select(length == 2 and (.[0] | length) == 2 and .[0][0] == "managed_env") | .[0][1]
' "${map_file}" | sort > "${tmp}/mapped-source"
[[ "$(wc -l < "${tmp}/mapped-source")" -eq "$(sort -u "${tmp}/mapped-source" | wc -l)" ]] || {
  printf 'error: deployment environment map contains duplicate source keys\n' >&2; exit 1;
}
[[ "$(wc -l < "${tmp}/mapped")" -eq "$(jq '.managed_env | length' "${map_file}")" ]] || {
  printf 'error: every map entry must be variable or secret\n' >&2; exit 1;
}
if ! cmp --silent "${tmp}/managed" "${tmp}/mapped"; then
  printf 'error: deployment environment map and managed key allowlist differ\n' >&2
  comm -3 "${tmp}/managed" "${tmp}/mapped" >&2
  exit 1
fi
jq -e '
  .actions.variable_fragment == "MIDORIVPN_DEPLOY_VALUES" and
  .actions.secret_fragment == "MIDORIVPN_DEPLOY_SECRETS" and
  (.actions.ssh | type == "object") and
  (.actions.registry | type == "object")
' "${map_file}" >/dev/null
printf 'Deployment environment map covers %s keys exactly once.\n' "$(wc -l < "${tmp}/managed")"
