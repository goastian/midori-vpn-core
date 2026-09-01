#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_FILE="${1:-${ROOT_DIR}/tmp/release-evidence/workspace-manifest.json}"
ALLOW_DIRTY="${ALLOW_DIRTY_RELEASE_BUILD:-false}"
REPOSITORIES=(
  ".:core"
  "midori-vpn-control:control"
  "midori-vpn-desktop:desktop"
  "midorivpn-extension:extension"
)

for command_name in git jq; do
  command -v "${command_name}" >/dev/null || { echo "error: ${command_name} is required" >&2; exit 1; }
done

expected_version="$(<"${ROOT_DIR}/VERSION")"
[[ "${expected_version}" == "2.0.0" ]] || { echo "error: Core VERSION must be 2.0.0" >&2; exit 1; }
for package_file in \
  "${ROOT_DIR}/midori-vpn-control/package.json" \
  "${ROOT_DIR}/midori-vpn-desktop/package.json" \
  "${ROOT_DIR}/midorivpn-extension/package.json"; do
  [[ "$(jq -r .version "${package_file}")" == "${expected_version}" ]] || {
    echo "error: version mismatch in ${package_file}" >&2
    exit 1
  }
done
[[ "$(jq -r .version "${ROOT_DIR}/midorivpn-extension/manifest/main.json")" == "${expected_version}" ]] || {
  echo "error: extension manifest version mismatch" >&2
  exit 1
}
[[ "$(awk '$1 == "Version:" {print $2; exit}' "${ROOT_DIR}/midori-vpn-desktop/packaging/midori-vpn.spec")" == "${expected_version}" ]] || {
  echo "error: RPM spec version mismatch" >&2
  exit 1
}

epoch="${SOURCE_DATE_EPOCH:-$(git -C "${ROOT_DIR}" show -s --format=%ct HEAD)}"
[[ "${epoch}" =~ ^[0-9]+$ ]] || { echo "error: SOURCE_DATE_EPOCH must be an integer" >&2; exit 1; }

entries=()
for repository in "${REPOSITORIES[@]}"; do
  relative_path="${repository%%:*}"
  component="${repository##*:}"
  repository_path="${ROOT_DIR}/${relative_path}"
  branch="$(git -C "${repository_path}" branch --show-current)"
  commit="$(git -C "${repository_path}" rev-parse HEAD)"

  if [[ "${branch}" != "dev-wedc" ]]; then
    echo "error: ${component} must be on local branch dev-wedc (found ${branch:-detached})" >&2
    exit 1
  fi
  if [[ "${ALLOW_DIRTY}" != "true" ]] && [[ -n "$(git -C "${repository_path}" status --short)" ]]; then
    echo "error: ${component} has uncommitted changes" >&2
    exit 1
  fi

  entries+=("$(printf '{\"component\":\"%s\",\"path\":\"%s\",\"branch\":\"%s\",\"commit\":\"%s\"}' \
    "${component}" "${relative_path}" "${branch}" "${commit}")")
done

mkdir -p "$(dirname "${OUTPUT_FILE}")"
{
  printf '{\n  "schema_version": 1,\n  "version": "%s",\n  "source_date_epoch": %s,\n  "repositories": [\n' "${expected_version}" "${epoch}"
  for index in "${!entries[@]}"; do
    [[ "${index}" -eq 0 ]] || printf ',\n'
    printf '    %s' "${entries[${index}]}"
  done
  printf '\n  ]\n}\n'
} > "${OUTPUT_FILE}"

echo "Workspace release manifest: ${OUTPUT_FILE}"
