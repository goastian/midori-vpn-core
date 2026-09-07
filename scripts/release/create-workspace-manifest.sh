#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_FILE="${1:-${ROOT_DIR}/tmp/release-evidence/workspace-manifest.json}"
ALLOW_DIRTY="${ALLOW_DIRTY_RELEASE_BUILD:-false}"
# shellcheck source=scripts/lib/workspace-layout.sh
source "${ROOT_DIR}/scripts/lib/workspace-layout.sh"

die() {
  echo "error: $*" >&2
  exit 1
}

CONTROL_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midori-vpn-control || true)"
DESKTOP_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midori-vpn-desktop || true)"
EXTENSION_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midorivpn-extension || true)"
[[ -n "${CONTROL_DIR}" ]] || die "Control repository was not found nested under Core or beside it"
[[ -n "${DESKTOP_DIR}" ]] || die "Desktop repository was not found nested under Core or beside it"
[[ -n "${EXTENSION_DIR}" ]] || die "Extension repository was not found nested under Core or beside it"

REPOSITORY_PATHS=("${ROOT_DIR}" "${CONTROL_DIR}" "${DESKTOP_DIR}" "${EXTENSION_DIR}")
REPOSITORY_NAMES=("." "midori-vpn-control" "midori-vpn-desktop" "midorivpn-extension")
REPOSITORY_COMPONENTS=("core" "control" "desktop" "extension")

for command_name in git jq; do
  command -v "${command_name}" >/dev/null || { echo "error: ${command_name} is required" >&2; exit 1; }
done

expected_version="$(<"${ROOT_DIR}/VERSION")"
[[ "${expected_version}" == "2.0.0" ]] || { echo "error: Core VERSION must be 2.0.0" >&2; exit 1; }
for package_file in \
  "${CONTROL_DIR}/package.json" \
  "${DESKTOP_DIR}/package.json" \
  "${EXTENSION_DIR}/package.json"; do
  [[ "$(jq -r .version "${package_file}")" == "${expected_version}" ]] || {
    echo "error: version mismatch in ${package_file}" >&2
    exit 1
  }
done
[[ "$(jq -r .version "${EXTENSION_DIR}/manifest/main.json")" == "${expected_version}" ]] || {
  echo "error: extension manifest version mismatch" >&2
  exit 1
}
[[ "$(awk '$1 == "Version:" {print $2; exit}' "${DESKTOP_DIR}/packaging/midori-vpn.spec")" == "${expected_version}" ]] || {
  echo "error: RPM spec version mismatch" >&2
  exit 1
}

epoch="${SOURCE_DATE_EPOCH:-$(git -C "${ROOT_DIR}" show -s --format=%ct HEAD)}"
[[ "${epoch}" =~ ^[0-9]+$ ]] || { echo "error: SOURCE_DATE_EPOCH must be an integer" >&2; exit 1; }
expected_branch="$(git -C "${ROOT_DIR}" branch --show-current)"
expected_ref_state="${expected_branch:-detached}"

entries=()
for index in "${!REPOSITORY_PATHS[@]}"; do
  repository_path="${REPOSITORY_PATHS[${index}]}"
  relative_path="${REPOSITORY_NAMES[${index}]}"
  component="${REPOSITORY_COMPONENTS[${index}]}"
  branch="$(git -C "${repository_path}" branch --show-current)"
  ref_state="${branch:-detached}"
  commit="$(git -C "${repository_path}" rev-parse HEAD)"

  if [[ "${branch}" != "${expected_branch}" ]]; then
    echo "error: ${component} ref state ${ref_state} must match Core ${expected_ref_state}" >&2
    exit 1
  fi
  if [[ "${ALLOW_DIRTY}" != "true" ]] && [[ -n "$(git -C "${repository_path}" status --short)" ]]; then
    echo "error: ${component} has uncommitted changes" >&2
    exit 1
  fi

  entries+=("$(printf '{\"component\":\"%s\",\"path\":\"%s\",\"branch\":\"%s\",\"commit\":\"%s\"}' \
    "${component}" "${relative_path}" "${ref_state}" "${commit}")")
done

mkdir -p "$(dirname "${OUTPUT_FILE}")"
{
  printf '{\n  "schema_version": 2,\n  "product_version": "%s",\n  "source_date_epoch": %s,\n  "repositories": [\n' "${expected_version}" "${epoch}"
  for entry_index in "${!entries[@]}"; do
    [[ "${entry_index}" -eq 0 ]] || printf ',\n'
    printf '    %s' "${entries[${entry_index}]}"
  done
  printf '\n  ]\n}\n'
} > "${OUTPUT_FILE}"

echo "Workspace release manifest: ${OUTPUT_FILE}"
