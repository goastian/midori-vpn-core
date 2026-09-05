#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

bundle=""
scope="rootless"
target_dir=""
backup_root=""
start_units=true
backup_record=""

usage() {
  printf 'usage: %s --bundle PATH [--scope rootless|rootful] [--target-dir PATH] [--backup-root PATH] [--backup-record FILE] [--no-start]\n' "$0"
}

while (($#)); do
  case "$1" in
    --bundle) bundle="${2:-}"; shift 2 ;;
    --scope) scope="${2:-}"; shift 2 ;;
    --target-dir) target_dir="${2:-}"; shift 2 ;;
    --backup-root) backup_root="${2:-}"; shift 2 ;;
    --backup-record) backup_record="${2:-}"; shift 2 ;;
    --no-start) start_units=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ -n "${bundle}" ]] || { usage >&2; host_die "--bundle is required"; }
[[ "${scope}" == rootless || "${scope}" == rootful ]] || host_die "--scope must be rootless or rootful"
host_require_private_directory "${bundle}"
host_require_regular_file "${bundle}/SHA256SUMS"
[[ ! -L "${bundle}/${scope}" && -d "${bundle}/${scope}" ]] || host_die "bundle has no ${scope} payload"
if find "${bundle}" -type l -print -quit | grep -q .; then
  host_die "deployment bundle must not contain symlinks"
fi
calculated_manifest="$(mktemp "${TMPDIR:-/tmp}/midorivpn-manifest.XXXXXX")"
cleanup_manifest() { rm -f -- "${calculated_manifest}"; }
trap cleanup_manifest EXIT
(
  cd "${bundle}"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum
) > "${calculated_manifest}"
cmp --silent "${bundle}/SHA256SUMS" "${calculated_manifest}" || host_die "deployment bundle contents do not exactly match the checksum manifest"
(
  cd "${bundle}"
  sha256sum --check --strict SHA256SUMS >/dev/null
) || host_die "deployment bundle checksum verification failed"
rm -f -- "${calculated_manifest}"
trap - EXIT

if [[ "${scope}" == rootless ]]; then
  [[ "$(id -u)" != 0 ]] || host_die "rootless units must be installed by the dedicated unprivileged user"
  account_home=""
  if passwd_entry="$(getent passwd "$(id -u)" 2>/dev/null)"; then
    account_home="$(cut -d: -f6 <<< "${passwd_entry}")"
  fi
  account_home="${account_home:-${HOME:-}}"
  [[ "${account_home}" == /* ]] || host_die "current account has no absolute home directory"
  target_dir="${target_dir:-${account_home}/.config/containers/systemd/midorivpn}"
  backup_root="${backup_root:-${account_home}/.local/state/midorivpn-deploy/backups}"
  systemctl_cmd=(systemctl --user)
else
  [[ "$(id -u)" == 0 ]] || host_die "rootful gateway installation requires sudo or root"
  target_dir="${target_dir:-/etc/containers/systemd/midorivpn}"
  backup_root="${backup_root:-/var/lib/midorivpn-deploy/backups}"
  systemctl_cmd=(systemctl)
fi
[[ "${target_dir}" == /* && "$(basename -- "${target_dir}")" == midorivpn ]] || host_die "target must be an absolute dedicated directory named midorivpn"
if [[ "${scope}" == rootful ]] && ! find "${bundle}/rootful" -maxdepth 1 -type f -name '*.container' -print -quit | grep -q .; then
  host_die "rootful payload is empty; no rootful gateway was enabled"
fi

install -d -m 0700 -- "${backup_root}"
backup_dir="$(mktemp -d "${backup_root}/$(host_timestamp)-${scope}.XXXXXX")"
if [[ -e "${target_dir}" ]]; then
  [[ -d "${target_dir}" && ! -L "${target_dir}" ]] || host_die "target is not a real directory: ${target_dir}"
  cp -a -- "${target_dir}" "${backup_dir}/previous"
else
  : > "${backup_dir}/PREVIOUSLY_ABSENT"
  chmod 0600 "${backup_dir}/PREVIOUSLY_ABSENT"
fi
if [[ -n "${backup_record}" ]]; then
  [[ "${backup_record}" == /* ]] || host_die "--backup-record must be absolute"
  install -d -m 0700 -- "$(dirname -- "${backup_record}")"
  printf '%s\n' "${backup_dir}" > "${backup_record}"
  chmod 0600 "${backup_record}"
fi

parent_dir="$(dirname -- "${target_dir}")"
install -d -m 0700 -- "${parent_dir}"
staged_target="$(mktemp -d "${parent_dir}/.midorivpn-install.XXXXXX")"
retired_target=""
cleanup() { rm -rf -- "${staged_target:-}" "${retired_target:-}"; }
trap cleanup EXIT
cp -a -- "${bundle}/${scope}/." "${staged_target}/"
find "${staged_target}" -type d -exec chmod 0700 {} +
find "${staged_target}" -type f -exec chmod 0600 {} +

if [[ -d "${target_dir}" ]]; then
  retired_target="${parent_dir}/.midorivpn-retired.$$"
  mv -- "${target_dir}" "${retired_target}"
fi
mv -- "${staged_target}" "${target_dir}"
staged_target=""

rollback_units() {
  rm -rf -- "${target_dir}"
  if [[ -d "${backup_dir}/previous" ]]; then
    cp -a -- "${backup_dir}/previous" "${target_dir}"
  fi
  if "${systemctl_cmd[@]}" daemon-reload; then
    old_units=()
    if [[ -d "${target_dir}" ]]; then
      if [[ "${scope}" == rootless ]]; then
        if [[ -f "${target_dir}/midorivpn-control.container" ]]; then
          old_units=(midorivpn-control.service midorivpn-grafana.service)
        elif [[ -f "${target_dir}/midorivpn-core.container" ]]; then
          old_units=(midorivpn-core.service)
        fi
      else
        [[ -f "${target_dir}/midorivpn-openvpn.container" ]] && old_units+=(midorivpn-openvpn.service)
        [[ -f "${target_dir}/midorivpn-ikev2.container" ]] && old_units+=(midorivpn-ikev2.service)
      fi
    fi
    ((${#old_units[@]} == 0)) || "${systemctl_cmd[@]}" enable --now "${old_units[@]}" || true
  fi
}

if ! "${systemctl_cmd[@]}" daemon-reload; then
  rollback_units
  host_die "systemd reload failed; the previous unit directory was restored"
fi

if [[ "${start_units}" == true ]]; then
  stop_units=()
  for unit_base in midorivpn-grafana midorivpn-prometheus midorivpn-control midorivpn-core midorivpn-pgbouncer midorivpn-db-finalize midorivpn-migrate midorivpn-db-prepare midorivpn-redis midorivpn-postgres midorivpn-openvpn midorivpn-ikev2; do
    if [[ -f "${target_dir}/${unit_base}.container" || -f "${backup_dir}/previous/${unit_base}.container" ]]; then
      stop_units+=("${unit_base}.service")
    fi
  done
  if [[ -f "${target_dir}/midorivpn.pod" || -f "${backup_dir}/previous/midorivpn.pod" ]]; then
    stop_units+=(midorivpn-pod.service)
  fi
  if ((${#stop_units[@]})) && ! "${systemctl_cmd[@]}" stop "${stop_units[@]}"; then
    rollback_units
    host_die "existing service shutdown failed; previous configuration was restored"
  fi
  if [[ "${scope}" == rootless ]]; then
    if [[ -f "${target_dir}/midorivpn-control.container" ]]; then
      units=(midorivpn-control.service midorivpn-grafana.service)
    else
      units=(midorivpn-core.service)
    fi
  else
    units=()
    [[ -f "${target_dir}/midorivpn-openvpn.container" ]] && units+=(midorivpn-openvpn.service)
    [[ -f "${target_dir}/midorivpn-ikev2.container" ]] && units+=(midorivpn-ikev2.service)
  fi
  if ((${#units[@]})) && ! "${systemctl_cmd[@]}" enable --now "${units[@]}"; then
    rollback_units
    host_die "unit startup failed; configuration was rolled back (database volumes were not changed)"
  fi
fi

rm -rf -- "${retired_target:-}"
retired_target=""
trap - EXIT
host_info "Installed ${scope} deployment: ${target_dir}"
host_info "Rollback snapshot: ${backup_dir}"
