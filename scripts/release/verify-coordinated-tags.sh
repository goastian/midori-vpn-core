#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT_DIR="${MIDORIVPN_WORKSPACE_ROOT:-${SCRIPT_ROOT}}"
TAG="${1:-}"
OUTPUT_FILE="${2:-${ROOT_DIR}/tmp/release-evidence/workspace-manifest.json}"
# shellcheck source=scripts/lib/workspace-layout.sh
source "${SCRIPT_ROOT}/scripts/lib/workspace-layout.sh"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ "${TAG}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] ||
  die "release tag must be semantic and start with v"
version="${TAG#v}"

for command_name in git jq; do
  command -v "${command_name}" >/dev/null || die "${command_name} is required"
done

CONTROL_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midori-vpn-control || true)"
DESKTOP_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midori-vpn-desktop || true)"
EXTENSION_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midorivpn-extension || true)"
[[ -n "${CONTROL_DIR}" ]] || die "Control repository was not found"
[[ -n "${DESKTOP_DIR}" ]] || die "Desktop repository was not found"
[[ -n "${EXTENSION_DIR}" ]] || die "Extension repository was not found"

paths=("${ROOT_DIR}" "${CONTROL_DIR}" "${DESKTOP_DIR}" "${EXTENSION_DIR}")
components=(core control desktop extension)
repositories=(
  goastian/midori-vpn-core
  goastian/midori-vpn-control
  goastian/midori-vpn-desktop
  goastian/midorivpn-extension
)

entries=()
for index in "${!paths[@]}"; do
  path="${paths[${index}]}"
  component="${components[${index}]}"
  repository="${repositories[${index}]}"
  [[ -z "$(git -C "${path}" status --short)" ]] || die "${component} checkout is dirty"
  git -C "${path}" show-ref --verify --quiet "refs/tags/${TAG}" || die "${component} lacks ${TAG}"
  [[ "$(git -C "${path}" cat-file -t "refs/tags/${TAG}")" == tag ]] ||
    die "${component} ${TAG} is not an annotated tag"
  commit="$(git -C "${path}" rev-parse "refs/tags/${TAG}^{}")"
  [[ "${commit}" == "$(git -C "${path}" rev-parse HEAD)" ]] ||
    die "${component} checkout does not match ${TAG}"
  tagger_epoch="$(git -C "${path}" for-each-ref --format='%(taggerdate:unix)' "refs/tags/${TAG}")"
  [[ "${tagger_epoch}" =~ ^[0-9]+$ ]] || die "${component} annotated tag has no tagger timestamp"
  entries+=("$(jq -cn \
    --arg component "${component}" \
    --arg repository "${repository}" \
    --arg tag "${TAG}" \
    --arg commit "${commit}" \
    --argjson tagger_epoch "${tagger_epoch}" \
    '{component:$component,repository:$repository,tag:$tag,commit:$commit,tagger_epoch:$tagger_epoch}')")
done

[[ "$(<"${ROOT_DIR}/VERSION")" == "${version}" ]] || die "Core VERSION does not match ${TAG}"
for package_file in "${CONTROL_DIR}/package.json" "${DESKTOP_DIR}/package.json" "${EXTENSION_DIR}/package.json"; do
  [[ "$(jq -r .version "${package_file}")" == "${version}" ]] || die "version mismatch in ${package_file}"
done
[[ "$(jq -r .version "${EXTENSION_DIR}/manifest/main.json")" == "${version}" ]] ||
  die "extension manifest version does not match ${TAG}"
[[ "$(awk '$1 == "Version:" {print $2; exit}' "${DESKTOP_DIR}/packaging/midori-vpn.spec")" == "${version}" ]] ||
  die "RPM spec version does not match ${TAG}"

source_date_epoch="$(git -C "${ROOT_DIR}" show -s --format=%ct HEAD)"
mkdir -p -- "$(dirname -- "${OUTPUT_FILE}")"
jq -n \
  --arg version "${version}" \
  --arg tag "${TAG}" \
  --argjson source_date_epoch "${source_date_epoch}" \
  --argjson repositories "$(printf '%s\n' "${entries[@]}" | jq -s .)" \
  '{schema_version:2,version:$version,tag:$tag,source_date_epoch:$source_date_epoch,repositories:$repositories}' \
  > "${OUTPUT_FILE}"
chmod 0600 "${OUTPUT_FILE}"
jq -e '.repositories | length == 4' "${OUTPUT_FILE}" >/dev/null
printf 'Coordinated annotated tags verified: %s\n' "${TAG}"
printf 'Workspace release manifest: %s\n' "${OUTPUT_FILE}"
