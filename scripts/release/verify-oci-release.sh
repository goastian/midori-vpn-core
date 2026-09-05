#!/usr/bin/env bash
set -Eeuo pipefail

component="${1:-}"
digest="${2:-}"
tag="${3:-v2.0.0}"

case "${component}" in
  core)
    image_name="ghcr.io/goastian/midori-vpn-core"
    repository="goastian/midori-vpn-core"
    ;;
  control)
    image_name="ghcr.io/goastian/midori-vpn-control"
    repository="goastian/midori-vpn-control"
    ;;
  *)
    echo "usage: $0 {core|control} sha256:<64 lowercase hexadecimal characters> [vSEMVER]" >&2
    exit 2
    ;;
esac

[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "error: an immutable sha256 digest is required" >&2
  exit 2
}
[[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] || {
  echo "error: an annotated semantic release tag is required" >&2
  exit 2
}

for command_name in cosign gh; do
  command -v "${command_name}" >/dev/null || { echo "error: ${command_name} is required" >&2; exit 1; }
done

image_ref="${image_name}@${digest}"
identity="https://github.com/${repository}/.github/workflows/publish.yml@refs/tags/${tag}"

cosign verify \
  --certificate-identity "${identity}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${image_ref}"

gh attestation verify "oci://${image_ref}" \
  --repo "${repository}" \
  --predicate-type https://slsa.dev/provenance/v1

gh attestation verify "oci://${image_ref}" \
  --repo "${repository}" \
  --predicate-type https://spdx.dev/Document/v2.3

echo "Verified ${component} release: ${image_ref}"
