#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
manifest=""
core_digest=""
control_digest=""
output_dir="${ROOT_DIR}/tmp/release-bundle"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'usage: %s --manifest FILE --core-digest SHA256 --control-digest SHA256 [--output-dir DIR]\n' "$0"
}

while (($#)); do
  case "$1" in
    --manifest) manifest="${2:-}"; shift 2 ;;
    --core-digest) core_digest="${2:-}"; shift 2 ;;
    --control-digest) control_digest="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ -f "${manifest}" && ! -L "${manifest}" ]] || die "a regular release manifest is required"
for digest in "${core_digest}" "${control_digest}"; do
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || die "image digests must be immutable sha256 values"
done
for command_name in jq tar gzip sha256sum; do
  command -v "${command_name}" >/dev/null || die "${command_name} is required"
done

jq -e '
  (.product_version + "-") as $prerelease_prefix |
  .schema_version == 3 and
  (.product_version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) and
  (.release_version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")) and
  (.release_version == .product_version or (.release_version | startswith($prerelease_prefix))) and
  .git_tag == ("v" + .release_version) and
  (.source_date_epoch | type == "number") and
  ([.repositories[].component] | sort) == ["control","core","desktop","extension"] and
  ([.repositories[].commit] | all(test("^[0-9a-f]{40}$")))
' "${manifest}" >/dev/null || die "release manifest is malformed or incomplete"

product_version="$(jq -r .product_version "${manifest}")"
release_version="$(jq -r .release_version "${manifest}")"
tag="$(jq -r .git_tag "${manifest}")"
epoch="$(jq -r .source_date_epoch "${manifest}")"
schema_head="$(find "${ROOT_DIR}/internal/db/migrations" -maxdepth 1 -type f -name '*.up.sql' -printf '%f\n' | sort -V | tail -1 | sed -E 's/^0*([0-9]+)_.*/\1/')"
[[ "${schema_head}" =~ ^[0-9]+$ ]] || die "database schema head could not be derived"

[[ ! -e "${output_dir}" ]] || die "output directory already exists: ${output_dir}"
parent="$(dirname -- "${output_dir}")"
install -d -m 0700 -- "${parent}"
staging="$(mktemp -d "${parent}/.midorivpn-bundle.XXXXXX")"
cleanup() { rm -rf -- "${staging}"; }
trap cleanup EXIT
payload="${staging}/midorivpn-${release_version}"
install -d -m 0700 -- "${payload}/deploy" "${payload}/docs" "${payload}/scripts/release"

cp -a -- "${ROOT_DIR}/deploy/ci" "${ROOT_DIR}/deploy/host" "${ROOT_DIR}/deploy/nginx" \
  "${ROOT_DIR}/deploy/observability" "${ROOT_DIR}/deploy/postgres" \
  "${payload}/deploy/"
install -m 0600 -- "${ROOT_DIR}/deploy/DEPLOYMENT_PROFILES.md" \
  "${ROOT_DIR}/deploy/POSTGRESQL.md" "${ROOT_DIR}/deploy/OBSERVABILITY.md" \
  "${ROOT_DIR}/deploy/OPENVPN.md" "${ROOT_DIR}/deploy/IKEV2.md" \
  "${ROOT_DIR}/deploy/WSS_TUNNEL.md" "${ROOT_DIR}/deploy/MASQUE.md" \
  "${payload}/deploy/"
install -m 0600 -- "${ROOT_DIR}/docs/PRODUCTION_DEPLOYMENT.md" \
  "${ROOT_DIR}/docs/RELEASE_OPERATIONS.md" \
  "${ROOT_DIR}/docs/RELEASE_SUPPLY_CHAIN.md" \
  "${ROOT_DIR}/docs/CENTRAL_CONTROL_ARCHITECTURE.md" \
  "${ROOT_DIR}/docs/openapi.yaml" "${payload}/docs/"
install -m 0600 -- "${ROOT_DIR}/.env.example" "${payload}/.env.example"
install -d -m 0700 -- "${payload}/deploy/grafana"
install -m 0600 -- "${ROOT_DIR}/deploy/grafana/midori-vpn-dashboard.json" "${payload}/deploy/grafana/"
install -m 0600 -- "${ROOT_DIR}/scripts/backup-postgres.sh" \
  "${ROOT_DIR}/scripts/restore-postgres-backup.sh" "${payload}/scripts/"
install -m 0600 -- "${ROOT_DIR}/scripts/release/compose-deployment-values.sh" \
  "${ROOT_DIR}/scripts/release/validate-deployment-environment-map.sh" \
  "${ROOT_DIR}/scripts/release/resolve-runtime-images.sh" \
  "${ROOT_DIR}/scripts/release/verify-oci-release.sh" \
  "${ROOT_DIR}/scripts/release/database-backup-gate.sh" \
  "${ROOT_DIR}/scripts/release/apply-deployment.sh" "${payload}/scripts/release/"
install -m 0600 -- "${manifest}" "${payload}/workspace-manifest.json"

jq -n \
  --arg product_version "${product_version}" --arg release_version "${release_version}" --arg git_tag "${tag}" \
  --arg core_pull_ref "ghcr.io/goastian/midori-vpn-core:${release_version}" \
  --arg core_digest "${core_digest}" \
  --arg core_verification_ref "ghcr.io/goastian/midori-vpn-core@${core_digest}" \
  --arg control_pull_ref "ghcr.io/goastian/midori-vpn-control:${release_version}" \
  --arg control_digest "${control_digest}" \
  --arg control_verification_ref "ghcr.io/goastian/midori-vpn-control@${control_digest}" \
  --argjson database_schema_head "${schema_head}" \
  '{schema_version:2,product_version:$product_version,release_version:$release_version,git_tag:$git_tag,images:{core:{pull_ref:$core_pull_ref,digest:$core_digest,verification_ref:$core_verification_ref,source_repository:"goastian/midori-vpn-core-dev",workflow_identity:("https://github.com/goastian/midori-vpn-core-dev/.github/workflows/publish.yml@refs/tags/" + $git_tag)},control:{pull_ref:$control_pull_ref,digest:$control_digest,verification_ref:$control_verification_ref,source_repository:"goastian/midori-vpn-control-dev",workflow_identity:("https://github.com/goastian/midori-vpn-control-dev/.github/workflows/publish.yml@refs/tags/" + $git_tag)}},database:{minimum_schema:0,target_schema:$database_schema_head,automatic_restore:false}}' \
  > "${payload}/release.json"

if find "${payload}" -type l -print -quit | grep -q .; then
  die "deployment bundle may not contain symlinks"
fi
if rg -n --hidden --glob '!SHA256SUMS' --glob '!*.template' \
  -- '-----BEGIN (OPENSSH|PRIVATE) KEY-----|ghp_[A-Za-z0-9]{20,}|github_pat_' "${payload}" >/dev/null; then
  die "deployment bundle contains private-key or token material"
fi
find "${payload}" -type d -exec chmod 0700 {} +
find "${payload}" -type f -exec chmod 0600 {} +
(
  cd -- "${payload}"
  checksum_tmp="$(mktemp .SHA256SUMS.XXXXXX)"
  find . -type f ! -name SHA256SUMS ! -name '.SHA256SUMS.*' -print0 | sort -z | xargs -0 sha256sum > "${checksum_tmp}"
  mv -- "${checksum_tmp}" SHA256SUMS
  sha256sum --check --strict SHA256SUMS >/dev/null
)

mv -- "${payload}" "${output_dir}"
archive="${output_dir}.tar.gz"
tar --sort=name --format=posix --mtime="@${epoch}" --owner=0 --group=0 --numeric-owner \
  --pax-option=delete=atime,delete=ctime -C "${parent}" -cf - "$(basename -- "${output_dir}")" |
  gzip -n -9 > "${archive}"
sha256sum "${archive}" > "${archive}.sha256"
chmod 0600 "${archive}" "${archive}.sha256"
trap - EXIT
rm -rf -- "${staging}"
printf 'Secret-free deployment bundle: %s\n' "${archive}"
printf 'Bundle checksum: %s\n' "${archive}.sha256"
