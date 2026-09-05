#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

bundle_dir=""
values_file=""
service_user="midorivpn"
deployment_id=""
issue_certificate=false

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() {
  printf 'usage: %s --bundle-dir DIR --values-file FILE [--service-user USER] [--deployment-id ID] [--issue-certificate]\n' "$0"
}
while (($#)); do
  case "$1" in
    --bundle-dir) bundle_dir="${2:-}"; shift 2 ;;
    --values-file) values_file="${2:-}"; shift 2 ;;
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
if find "${bundle_dir}" -type l -print -quit | grep -q .; then die "bundle contains symlinks"; fi
(cd -- "${bundle_dir}" && sha256sum --check --strict SHA256SUMS >/dev/null) || die "bundle checksum validation failed"
jq -e '
  .schema_version == 1 and
  (.version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")) and
  .tag == ("v" + .version) and
  (.images.core | test("^ghcr\\.io/goastian/midori-vpn-core@sha256:[0-9a-f]{64}$")) and
  (.images.control | test("^ghcr\\.io/goastian/midori-vpn-control@sha256:[0-9a-f]{64}$")) and
  .database.automatic_restore == false
' "${bundle_dir}/release.json" >/dev/null || die "release metadata is invalid"
version="$(jq -r .version "${bundle_dir}/release.json")"
deployment_id="${deployment_id:-${version}-$(date -u +%Y%m%dT%H%M%SZ)}"
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
install -m 0600 -o "${service_uid}" -g "${service_gid}" -- "${values_file}" "${record_root}/values.env"
chown -R "${service_uid}:${service_gid}" "${release_root}" "${record_root}"

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
rollback() {
  status=$?
  trap - ERR INT TERM
  set +e
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
  --values-file "${record_root}/values.env" --backup-record "${record_root}/env-backup"
env_changed=true

declare -A cfg=()
# shellcheck source=deploy/host/lib/common.sh
source "${release_root}/deploy/host/lib/common.sh"
host_load_env "${env_file}" cfg
[[ "${cfg[CORE_IMAGE]:-}" == "$(jq -r .images.core "${release_root}/release.json")" ]] || host_die "configured Core image differs from verified release digest"
if [[ "${cfg[DEPLOYMENT_PROFILE]:-}" == principal ]]; then
  [[ "${cfg[CONTROL_IMAGE]:-}" == "$(jq -r .images.control "${release_root}/release.json")" ]] || host_die "configured Control image differs from verified release digest"
fi

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
