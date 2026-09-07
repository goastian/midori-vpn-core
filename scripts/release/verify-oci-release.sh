#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
component="${1:-}"
release_json="${2:-}"
workspace_manifest="${3:-}"
container_engine="${CONTAINER_ENGINE:-docker}"
# shellcheck source=deploy/host/lib/common.sh
source "${ROOT_DIR}/deploy/host/lib/common.sh"

case "${component}" in
  core)
    expected_image_name="ghcr.io/goastian/midori-vpn-core"
    expected_repository="goastian/midori-vpn-core-dev"
    ;;
  control)
    expected_image_name="ghcr.io/goastian/midori-vpn-control"
    expected_repository="goastian/midori-vpn-control-dev"
    ;;
  *)
    printf 'usage: %s {core|control} RELEASE_JSON WORKSPACE_MANIFEST\n' "$0" >&2
    exit 2
    ;;
esac

host_require_regular_file "${release_json}"
host_require_regular_file "${workspace_manifest}"
case "${container_engine}" in
  docker|podman) ;;
  *) host_die "CONTAINER_ENGINE must be docker or podman" ;;
esac
for command_name in "${container_engine}" cosign gh jq; do
  host_require_command "${command_name}"
done

pull_ref="$(jq -er --arg component "${component}" '.images[$component].pull_ref' "${release_json}")"
digest="$(jq -er --arg component "${component}" '.images[$component].digest' "${release_json}")"
verification_ref="$(jq -er --arg component "${component}" '.images[$component].verification_ref' "${release_json}")"
repository="$(jq -er --arg component "${component}" '.images[$component].source_repository' "${release_json}")"
identity="$(jq -er --arg component "${component}" '.images[$component].workflow_identity' "${release_json}")"
release_version="$(jq -er .release_version "${release_json}")"
git_tag="$(jq -er .git_tag "${release_json}")"
expected_commit="$(jq -er --arg component "${component}" '.repositories[] | select(.component == $component) | .commit' "${workspace_manifest}")"

host_validate_versioned_image "${pull_ref}" "${component} image"
[[ "${pull_ref}" == "${expected_image_name}:${release_version}" ]] || host_die "${component} pull tag is inconsistent"
[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || host_die "${component} expected digest is invalid"
[[ "${verification_ref}" == "${expected_image_name}@${digest}" ]] || host_die "${component} verification reference is inconsistent"
[[ "${repository}" == "${expected_repository}" ]] || host_die "${component} source repository is inconsistent"
[[ "${identity}" == "https://github.com/${expected_repository}/.github/workflows/publish.yml@refs/tags/${git_tag}" ]] ||
  host_die "${component} workflow identity is inconsistent"

"${container_engine}" pull --quiet "${pull_ref}" >/dev/null
if ! "${container_engine}" image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${pull_ref}" |
  grep -Fxq "${verification_ref}"; then
  host_die "${component} tag does not resolve to the approved digest"
fi
actual_commit="$("${container_engine}" image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "${pull_ref}")"
actual_version="$("${container_engine}" image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "${pull_ref}")"
[[ "${actual_commit}" == "${expected_commit}" ]] || host_die "${component} image revision label is invalid"
[[ "${actual_version}" == "${release_version}" ]] || host_die "${component} image version label is invalid"

cosign verify \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${verification_ref}"

gh attestation verify "oci://${verification_ref}" \
  --repo "${repository}" \
  --predicate-type https://slsa.dev/provenance/v1

gh attestation verify "oci://${verification_ref}" \
  --repo "${repository}" \
  --predicate-type https://spdx.dev/Document/v2.3

printf 'Verified %s tag %s at %s\n' "${component}" "${pull_ref}" "${digest}"
