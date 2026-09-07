#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

bundle_dir=""
values_file=""
image_lock=""
service_user="midorivpn"
deployment_id=""
issue_certificate=false

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() {
  printf 'usage: %s --bundle-dir DIR --values-file FILE --image-lock FILE [--service-user USER] [--deployment-id ID] [--issue-certificate]\n' "$0"
}
while (($#)); do
  case "$1" in
    --bundle-dir) bundle_dir="${2:-}"; shift 2 ;;
    --values-file) values_file="${2:-}"; shift 2 ;;
    --image-lock) image_lock="${2:-}"; shift 2 ;;
    --service-user) service_user="${2:-}"; shift 2 ;;
    --deployment-id) deployment_id="${2:-}"; shift 2 ;;
    --issue-certificate) issue_certificate=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done
[[ "$(id -u)" == 0 ]] || die "deployment orchestration must run through sudo or as root"
[[ "${service_user}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid service user"
[[ -d "${bundle_dir}" && ! -L "${bundle_dir}" ]] || die "bundle directory is invalid"
[[ -f "${bundle_dir}/SHA256SUMS" && ! -L "${bundle_dir}/SHA256SUMS" ]] || die "bundle checksum manifest is missing"
[[ -f "${values_file}" && ! -L "${values_file}" ]] || die "deployment values file is invalid"
[[ -f "${image_lock}" && ! -L "${image_lock}" ]] || die "runtime image lock is invalid"
if find "${bundle_dir}" -type l -print -quit | grep -q .; then die "bundle contains symlinks"; fi
(cd -- "${bundle_dir}" && sha256sum --check --strict SHA256SUMS >/dev/null) || die "bundle checksum validation failed"
jq -e '
  (.product_version + "-") as $prerelease_prefix |
  .schema_version == 2 and
  (.product_version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) and
  (.release_version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")) and
  (.release_version == .product_version or (.release_version | startswith($prerelease_prefix))) and
  .git_tag == ("v" + .release_version) and
  (.images.core.pull_ref == ("ghcr.io/goastian/midori-vpn-core:" + .release_version)) and
  (.images.control.pull_ref == ("ghcr.io/goastian/midori-vpn-control:" + .release_version)) and
  (.images.core.digest | test("^sha256:[0-9a-f]{64}$")) and
  (.images.control.digest | test("^sha256:[0-9a-f]{64}$")) and
  .images.core.verification_ref == ("ghcr.io/goastian/midori-vpn-core@" + .images.core.digest) and
  .images.control.verification_ref == ("ghcr.io/goastian/midori-vpn-control@" + .images.control.digest) and
  .database.automatic_restore == false
' "${bundle_dir}/release.json" >/dev/null || die "release metadata is invalid"
release_version="$(jq -r .release_version "${bundle_dir}/release.json")"
deployment_id="${deployment_id:-${release_version}-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "${deployment_id}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$ ]] || die "invalid deployment id"

bash "${bundle_dir}/deploy/host/prepare-opensuse.sh" --apply --service-user "${service_user}"
service_entry="$(getent passwd "${service_user}")"
service_uid="$(cut -d: -f3 <<< "${service_entry}")"
service_gid="$(cut -d: -f4 <<< "${service_entry}")"
service_home="$(cut -d: -f6 <<< "${service_entry}")"
[[ "${service_home}" == /* ]] || die "service account has no absolute home"
runtime_env=(HOME="${service_home}" XDG_RUNTIME_DIR="/run/user/${service_uid}" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${service_uid}/bus")
run_service() { runuser -u "${service_user}" -- env "${runtime_env[@]}" "$@"; }

state_root="${service_home}/.local/state/midorivpn-deploy"
release_root="${state_root}/releases/${deployment_id}"
record_root="${state_root}/runs/${deployment_id}"
env_file="${service_home}/.config/midorivpn/midorivpn.env"
[[ ! -e "${release_root}" && ! -e "${record_root}" ]] || die "deployment id already exists"
install -d -m 0700 -o "${service_uid}" -g "${service_gid}" "${release_root}" "${record_root}"
cp -a -- "${bundle_dir}/." "${release_root}/"
chown -R "${service_uid}:${service_gid}" "${release_root}" "${record_root}"
staged_values="${record_root}/.deployment-values.env"
install -m 0600 -o "${service_uid}" -g "${service_gid}" -- "${values_file}" "${staged_values}"
verified_image_lock="${record_root}/runtime-images.json"
install -m 0600 -- "${image_lock}" "${verified_image_lock}"
cleanup_staged_values() { rm -f -- "${staged_values}"; }
trap cleanup_staged_values EXIT

# A running principal is backed up and restored into an isolated database before
# any configuration or unit is changed. A new empty host has no data to back up.
if [[ -f "${env_file}" ]] && run_service podman container exists midorivpn-postgres; then
  run_service bash "${release_root}/scripts/release/database-backup-gate.sh" \
    "${env_file}" "${service_home}/backups/midorivpn/${deployment_id}"
fi

env_changed=false
units_changed=false
rootful_changed=false
nginx_changed=false
firewall_changed=false
rendered=""
rollback() {
  status=$?
  trap - ERR INT TERM
  set +e
  rm -f -- "${staged_values}"
  [[ -z "${rendered}" ]] || rm -rf -- "${rendered}"
  if [[ "${nginx_changed}" == true ]]; then
    nginx_backup="$(<"${record_root}/nginx-backup")"
    bash "${release_root}/deploy/host/rollback-nginx.sh" "${nginx_backup}"
  fi
  if [[ "${firewall_changed}" == true ]]; then
    firewall_backup="$(<"${record_root}/firewall-backup")"
    bash "${release_root}/deploy/host/rollback-firewall.sh" "${firewall_backup}"
  fi
  if [[ "${rootful_changed}" == true ]]; then
    rootful_backup="$(<"${record_root}/rootful-backup")"
    bash "${release_root}/deploy/host/rollback.sh" --scope rootful --backup-dir "${rootful_backup}" --target-dir /etc/containers/systemd/midorivpn --restart
  fi
  if [[ "${units_changed}" == true ]]; then
    unit_backup="$(<"${record_root}/rootless-backup")"
    run_service bash "${release_root}/deploy/host/rollback.sh" --backup-dir "${unit_backup}" --target-dir "${service_home}/.config/containers/systemd/midorivpn" --restart
  fi
  if [[ "${env_changed}" == true ]]; then
    env_backup="$(<"${record_root}/env-backup")"
    if [[ "${env_backup}" == ABSENT ]]; then
      rm -f -- "${env_file}"
    else
      run_service bash "${release_root}/deploy/host/restore-env.sh" --env-file "${env_file}" --backup-file "${env_backup}"
    fi
  fi
  printf 'error: deployment failed; application and configuration rollback attempted; database data was not restored\n' >&2
  exit "${status}"
}
trap rollback ERR INT TERM

run_service bash "${release_root}/deploy/host/patch-env.sh" --env-file "${env_file}" \
  --values-file "${staged_values}" --backup-record "${record_root}/env-backup"
env_changed=true
rm -f -- "${staged_values}"

declare -A cfg=()
# shellcheck source=deploy/host/lib/common.sh
source "${release_root}/deploy/host/lib/common.sh"
host_load_env "${env_file}" cfg
[[ "${cfg[CORE_IMAGE]:-}" == "$(jq -r .images.core.pull_ref "${release_root}/release.json")" ]] || host_die "configured Core image differs from verified release tag"
if [[ "${cfg[DEPLOYMENT_PROFILE]:-}" == principal ]]; then
  [[ "${cfg[CONTROL_IMAGE]:-}" == "$(jq -r .images.control.pull_ref "${release_root}/release.json")" ]] || host_die "configured Control image differs from verified release tag"
fi

jq -e --arg profile "${cfg[DEPLOYMENT_PROFILE]:-}" \
  --arg product_version "$(jq -r .product_version "${release_root}/release.json")" \
  --arg release_version "${release_version}" \
  --arg git_tag "$(jq -r .git_tag "${release_root}/release.json")" '
  .schema_version == 1 and
  .deployment_profile == $profile and
  .product_version == $product_version and
  .release_version == $release_version and
  .git_tag == $git_tag and
  (.images | type == "array") and
  ([.images[].key] | length == (unique | length)) and
  ([.images[]] | all(
    (.key | test("^[A-Z][A-Z0-9_]*_IMAGE$")) and
    (.pull_ref | type == "string") and
    (.digest | test("^sha256:[0-9a-f]{64}$")) and
    .verification_ref == ((.pull_ref | sub(":[^:]+$"; "")) + "@" + .digest)
  ))
' "${verified_image_lock}" >/dev/null || host_die "runtime image lock metadata is invalid"

runtime_image_keys=(CORE_IMAGE POD_INFRA_IMAGE REDIS_IMAGE)
if [[ "${cfg[DEPLOYMENT_PROFILE]}" == principal ]]; then
  runtime_image_keys+=(CONTROL_IMAGE POSTGRES_IMAGE PGBOUNCER_IMAGE PROMETHEUS_IMAGE GRAFANA_IMAGE)
fi
for gateway in OPENVPN IKEV2; do
  if [[ "${cfg[${gateway}_ENABLED]:-false}" == true ]]; then
    runtime_image_keys+=("${gateway}_IMAGE")
  fi
done
[[ "$(jq '.images | length' "${verified_image_lock}")" == "${#runtime_image_keys[@]}" ]] ||
  host_die "runtime image lock has an unexpected number of entries"

for image_key in "${runtime_image_keys[@]}"; do
  locked_pull_ref="$(jq -er --arg key "${image_key}" '.images[] | select(.key == $key) | .pull_ref' "${verified_image_lock}")"
  locked_digest="$(jq -er --arg key "${image_key}" '.images[] | select(.key == $key) | .digest' "${verified_image_lock}")"
  locked_verification_ref="$(jq -er --arg key "${image_key}" '.images[] | select(.key == $key) | .verification_ref' "${verified_image_lock}")"
  [[ "${cfg[${image_key}]:-}" == "${locked_pull_ref}" ]] || host_die "${image_key} differs from the runtime image lock"
  host_validate_versioned_image "${locked_pull_ref}" "${image_key}"
  [[ "${locked_verification_ref}" == "${locked_pull_ref%:*}@${locked_digest}" ]] ||
    host_die "${image_key} lock reference is inconsistent"

  run_service podman pull --quiet "${locked_pull_ref}" >/dev/null
  if ! run_service podman image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${locked_pull_ref}" |
    grep -Fxq "${locked_verification_ref}"; then
    host_die "${image_key} tag changed after the protected verification gate"
  fi

  case "${image_key}" in
    CORE_IMAGE) component=core ;;
    CONTROL_IMAGE) component=control ;;
    *) component="" ;;
  esac
  if [[ -n "${component}" ]]; then
    expected_commit="$(jq -er --arg component "${component}" '.repositories[] | select(.component == $component) | .commit' "${release_root}/workspace-manifest.json")"
    actual_commit="$(run_service podman image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "${locked_pull_ref}")"
    actual_version="$(run_service podman image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "${locked_pull_ref}")"
    [[ "${actual_commit}" == "${expected_commit}" ]] || host_die "${image_key} revision label differs from the coordinated commit"
    [[ "${actual_version}" == "${release_version}" ]] || host_die "${image_key} version label differs from the release"
  fi
done

rendered="${record_root}/rendered"
run_service bash "${release_root}/deploy/host/render-quadlets.sh" --env-file "${env_file}" \
  --output-dir "${rendered}" --runtime-dir "${service_home}/.config/containers/systemd/midorivpn"
run_service bash "${release_root}/deploy/host/install-quadlets.sh" --bundle "${rendered}" \
  --backup-record "${record_root}/rootless-backup"
units_changed=true

if find "${rendered}/rootful" -maxdepth 1 -type f -name '*.container' -print -quit | grep -q .; then
  bash "${release_root}/deploy/host/install-quadlets.sh" --scope rootful --bundle "${rendered}" \
    --backup-record "${record_root}/rootful-backup"
  rootful_changed=true
fi
rm -rf -- "${rendered}"
rendered=""
bash "${release_root}/deploy/host/configure-firewall.sh" --env-file "${env_file}" --apply \
  --backup-record "${record_root}/firewall-backup"
firewall_changed=true
nginx_args=(--env-file "${env_file}" --backup-record "${record_root}/nginx-backup")
[[ "${issue_certificate}" == false ]] || nginx_args+=(--issue-certificate)
bash "${release_root}/deploy/host/configure-nginx.sh" "${nginx_args[@]}"
nginx_changed=true

health_args=(--edge-url "https://${cfg[DOMAIN]}/.well-known/midorivpn/edge-health" --core-url "http://127.0.0.1:${cfg[VPN_CORE_HOST_PORT]}/readyz")
if [[ "${cfg[DEPLOYMENT_PROFILE]}" == principal ]]; then
  health_args+=(--control-url "http://127.0.0.1:${cfg[CONTROL_HOST_PORT]}/")
fi
run_service bash "${release_root}/deploy/host/healthcheck.sh" "${health_args[@]}"

trap - ERR INT TERM
printf 'Deployment %s passed migration/startup and strict smoke gates.\n' "${deployment_id}"
printf 'Database backups were retained; no automatic data restore was performed.\n'
