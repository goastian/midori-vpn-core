#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
env_file=""
release_json=""
workspace_manifest=""
output_file=""
container_engine="${CONTAINER_ENGINE:-docker}"
# shellcheck source=deploy/host/lib/common.sh
source "${ROOT_DIR}/deploy/host/lib/common.sh"

usage() {
  printf 'usage: %s --env-file FILE --release-json FILE --workspace-manifest FILE --output FILE\n' "$0"
}

while (($#)); do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --release-json) release_json="${2:-}"; shift 2 ;;
    --workspace-manifest) workspace_manifest="${2:-}"; shift 2 ;;
    --output) output_file="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

for input_file in "${env_file}" "${release_json}" "${workspace_manifest}"; do
  host_require_regular_file "${input_file}"
done
[[ -n "${output_file}" ]] || { usage >&2; host_die "--output is required"; }
case "${container_engine}" in
  docker|podman) ;;
  *) host_die "CONTAINER_ENGINE must be docker or podman" ;;
esac
host_require_command "${container_engine}"
host_require_command jq

declare -A cfg=()
host_load_env "${env_file}" cfg
host_require_env cfg DEPLOYMENT_PROFILE
profile="${cfg[DEPLOYMENT_PROFILE]}"
[[ "${profile}" == principal || "${profile}" == core-node ]] || host_die "DEPLOYMENT_PROFILE must be principal or core-node"

image_keys=(CORE_IMAGE POD_INFRA_IMAGE REDIS_IMAGE)
if [[ "${profile}" == principal ]]; then
  image_keys+=(CONTROL_IMAGE POSTGRES_IMAGE PGBOUNCER_IMAGE PROMETHEUS_IMAGE GRAFANA_IMAGE)
fi
for gateway in OPENVPN IKEV2; do
  enabled_key="${gateway}_ENABLED"
  if [[ "${cfg[${enabled_key}]:-false}" == true ]]; then
    image_keys+=("${gateway}_IMAGE")
  fi
done

entries=()
for key in "${image_keys[@]}"; do
  host_require_env cfg "${key}"
  pull_ref="${cfg[${key}]}"
  host_validate_versioned_image "${pull_ref}" "${key}"
  "${container_engine}" pull --quiet "${pull_ref}" >/dev/null

  repository="${pull_ref%:*}"
  resolved_ref=""
  while IFS= read -r candidate; do
    if [[ "${candidate}" == "${repository}@sha256:"* ]]; then
      [[ -z "${resolved_ref}" || "${resolved_ref}" == "${candidate}" ]] ||
        host_die "${key} resolved to more than one repository digest"
      resolved_ref="${candidate}"
    fi
  done < <("${container_engine}" image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${pull_ref}")
  [[ "${resolved_ref}" =~ @sha256:[0-9a-f]{64}$ ]] || host_die "${key} did not resolve to a sha256 repository digest"
  resolved_digest="${resolved_ref##*@}"

  case "${key}" in
    CORE_IMAGE) component=core ;;
    CONTROL_IMAGE) component=control ;;
    *) component="" ;;
  esac
  if [[ -n "${component}" ]]; then
    expected_pull_ref="$(jq -er --arg component "${component}" '.images[$component].pull_ref' "${release_json}")"
    expected_digest="$(jq -er --arg component "${component}" '.images[$component].digest' "${release_json}")"
    expected_verification_ref="$(jq -er --arg component "${component}" '.images[$component].verification_ref' "${release_json}")"
    [[ "${pull_ref}" == "${expected_pull_ref}" ]] || host_die "${key} tag differs from release metadata"
    [[ "${resolved_digest}" == "${expected_digest}" ]] || host_die "${key} tag resolves to an unexpected digest"
    [[ "${resolved_ref}" == "${expected_verification_ref}" ]] || host_die "${key} verification reference is inconsistent"

    expected_commit="$(jq -er --arg component "${component}" '.repositories[] | select(.component == $component) | .commit' "${workspace_manifest}")"
    expected_version="$(jq -er '.release_version' "${release_json}")"
    actual_commit="$("${container_engine}" image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "${pull_ref}")"
    actual_version="$("${container_engine}" image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "${pull_ref}")"
    [[ "${actual_commit}" == "${expected_commit}" ]] || host_die "${key} revision label differs from the coordinated source commit"
    [[ "${actual_version}" == "${expected_version}" ]] || host_die "${key} version label differs from the release version"
  fi

  entries+=("$(jq -cn --arg key "${key}" --arg pull_ref "${pull_ref}" --arg digest "${resolved_digest}" --arg verification_ref "${resolved_ref}" \
    '{key:$key,pull_ref:$pull_ref,digest:$digest,verification_ref:$verification_ref}')")
done

output_dir="$(dirname -- "${output_file}")"
install -d -m 0700 -- "${output_dir}"
temporary="$(mktemp "${output_dir}/.$(basename -- "${output_file}").XXXXXX")"
cleanup() { rm -f -- "${temporary}"; }
trap cleanup EXIT
printf '%s\n' "${entries[@]}" | jq -s \
  --arg profile "${profile}" \
  --arg product_version "$(jq -er .product_version "${release_json}")" \
  --arg release_version "$(jq -er .release_version "${release_json}")" \
  --arg git_tag "$(jq -er .git_tag "${release_json}")" \
  '{schema_version:1,deployment_profile:$profile,product_version:$product_version,release_version:$release_version,git_tag:$git_tag,images:.}' \
  > "${temporary}"
chmod 0600 "${temporary}"
mv -f -- "${temporary}" "${output_file}"
trap - EXIT
printf 'Resolved and locked %s runtime image tags in %s\n' "${#entries[@]}" "${output_file}"
