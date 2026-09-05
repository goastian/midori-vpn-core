#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=deploy/host/lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

env_file=""
issue_certificate=false
backup_root="/var/lib/midorivpn-deploy/nginx-backups"

usage() {
  printf 'usage: %s --env-file PATH [--issue-certificate] [--backup-root PATH]\n' "$0"
}

while (($#)); do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --issue-certificate) issue_certificate=true; shift ;;
    --backup-root) backup_root="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; host_die "unknown argument: $1" ;;
  esac
done

[[ "$(id -u)" == 0 ]] || host_die "Nginx configuration requires sudo or root"
[[ -n "${env_file}" ]] || { usage >&2; host_die "--env-file is required"; }
host_require_command nginx
host_require_command systemctl
declare -A cfg=()
host_load_env "${env_file}" cfg
for key in DOMAIN VPN_CORE_HOST_PORT CONTROL_HOST_PORT ACME_WEBROOT NGINX_VHOST_PATH PROXY_ENABLED; do
  host_require_env cfg "${key}"
done
[[ "${cfg[DOMAIN]}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || host_die "DOMAIN is not a valid hostname"
for key in VPN_CORE_HOST_PORT CONTROL_HOST_PORT; do
  if [[ ! "${cfg[${key}]}" =~ ^[0-9]+$ ]] || ((cfg[${key}] < 1 || cfg[${key}] > 65535)); then
    host_die "${key} must be a valid port"
  fi
done
[[ "${cfg[ACME_WEBROOT]}" == /* ]] || host_die "ACME_WEBROOT must be absolute"
[[ "${cfg[NGINX_VHOST_PATH]}" == /etc/nginx/* ]] || host_die "NGINX_VHOST_PATH must remain below /etc/nginx"
[[ "${cfg[PROXY_ENABLED]}" == true || "${cfg[PROXY_ENABLED]}" == false ]] || host_die "PROXY_ENABLED must be true or false"

destinations=("${cfg[NGINX_VHOST_PATH]}")
templates=("${SOURCE_ROOT}/deploy/nginx/core-vhost.conf.template")
if [[ "${cfg[PROXY_ENABLED]}" == true ]]; then
  for key in NGINX_STREAM_VHOST_PATH PROXY_HOST_PORT PROXY_PORT; do
    host_require_env cfg "${key}"
  done
  [[ "${cfg[NGINX_STREAM_VHOST_PATH]}" == /etc/nginx/* ]] || host_die "NGINX_STREAM_VHOST_PATH must remain below /etc/nginx"
  for key in PROXY_HOST_PORT PROXY_PORT; do
    if [[ ! "${cfg[${key}]}" =~ ^[0-9]+$ ]] || ((cfg[${key}] < 1 || cfg[${key}] > 65535)); then
      host_die "${key} must be a valid port"
    fi
  done
  destinations+=("${cfg[NGINX_STREAM_VHOST_PATH]}")
  templates+=("${SOURCE_ROOT}/deploy/nginx/core-stream.conf.template")
fi

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-nginx.XXXXXX")"
cleanup() { rm -rf -- "${temporary_dir}"; }
trap cleanup EXIT

escape_sed() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }
sed \
  -e "s|__DOMAIN__|$(escape_sed "${cfg[DOMAIN]}")|g" \
  -e "s|__VPN_CORE_HOST_PORT__|$(escape_sed "${cfg[VPN_CORE_HOST_PORT]}")|g" \
  -e "s|__CONTROL_WEB_PORT__|$(escape_sed "${cfg[CONTROL_HOST_PORT]}")|g" \
  "${templates[0]}" > "${temporary_dir}/vhost.conf"
grep -Fq 'location = /.well-known/midorivpn/edge-health' "${temporary_dir}/vhost.conf" || host_die "rendered Nginx vhost lacks the exact edge-health route"
if grep -Eq '__[A-Z0-9_]+__' "${temporary_dir}/vhost.conf"; then
  host_die "rendered Nginx vhost contains unresolved placeholders"
fi

if [[ "${cfg[PROXY_ENABLED]}" == true ]]; then
  sed \
    -e "s|__DOMAIN__|$(escape_sed "${cfg[DOMAIN]}")|g" \
    -e "s|__PROXY_HOST_PORT__|$(escape_sed "${cfg[PROXY_HOST_PORT]}")|g" \
    -e "s|__PROXY_PUBLIC_PORT__|$(escape_sed "${cfg[PROXY_PORT]}")|g" \
    "${templates[1]}" > "${temporary_dir}/stream.conf"
  if grep -Eq '__[A-Z0-9_]+__' "${temporary_dir}/stream.conf"; then
    host_die "rendered Nginx stream config contains unresolved placeholders"
  fi
fi

install -d -m 0700 -- "${backup_root}"
backup_dir="$(mktemp -d "${backup_root}/$(host_timestamp).XXXXXX")"
atomic_nginx_install() {
  local source_path="$1" destination_path="$2" destination_parent temporary_path
  destination_parent="$(dirname -- "${destination_path}")"
  temporary_path="$(mktemp "${destination_parent}/.$(basename -- "${destination_path}").XXXXXX")"
  install -m 0644 -- "${source_path}" "${temporary_path}"
  sync -f "${temporary_path}"
  mv -f -- "${temporary_path}" "${destination_path}"
}
for index in "${!destinations[@]}"; do
  nginx_destination="${destinations[${index}]}"
  [[ ! -L "${nginx_destination}" ]] || host_die "refusing to replace symlink: ${nginx_destination}"
  install -d -m 0755 -- "$(dirname -- "${nginx_destination}")"
  if [[ -f "${nginx_destination}" ]]; then
    install -m 0600 -- "${nginx_destination}" "${backup_dir}/${index}.conf"
  else
    : > "${backup_dir}/${index}.absent"
    chmod 0600 "${backup_dir}/${index}.absent"
  fi
  if [[ "${index}" == 0 ]]; then
    rendered_name=vhost
  else
    rendered_name=stream
  fi
  atomic_nginx_install "${temporary_dir}/${rendered_name}.conf" "${nginx_destination}"
done

restore_nginx() {
  local restore_index restore_destination
  for restore_index in "${!destinations[@]}"; do
    restore_destination="${destinations[${restore_index}]}"
    if [[ -f "${backup_dir}/${restore_index}.conf" ]]; then
      atomic_nginx_install "${backup_dir}/${restore_index}.conf" "${restore_destination}"
    else
      rm -f -- "${restore_destination}"
    fi
  done
}

if ! nginx -t; then
  restore_nginx
  host_die "Nginx rejected the new configuration; previous files restored"
fi

if [[ "${issue_certificate}" == true ]]; then
  host_require_command certbot
  for key in CERTBOT_EMAIL LETSENCRYPT_STAGING; do
    host_require_env cfg "${key}"
  done
  [[ "${cfg[LETSENCRYPT_STAGING]}" == true || "${cfg[LETSENCRYPT_STAGING]}" == false ]] || host_die "LETSENCRYPT_STAGING must be true or false"
  install -d -m 0755 "${cfg[ACME_WEBROOT]}/.well-known/acme-challenge"
  certbot_args=(--nginx --domain "${cfg[DOMAIN]}" --email "${cfg[CERTBOT_EMAIL]}" --non-interactive --agree-tos --redirect --keep-until-expiring)
  [[ "${cfg[LETSENCRYPT_STAGING]}" == false ]] || certbot_args+=(--staging)
  certbot "${certbot_args[@]}" || { restore_nginx; host_die "Certbot failed; pre-Certbot vhost files restored"; }
  nginx -t || { restore_nginx; host_die "post-Certbot Nginx validation failed; prior vhost files restored"; }
fi

if ! systemctl reload nginx.service; then
  restore_nginx
  nginx -t || host_die "Nginx reload failed and the restored configuration is invalid"
  systemctl reload nginx.service || host_die "Nginx reload failed after restoring previous files"
  host_die "Nginx reload failed; previous files restored and reloaded"
fi
host_info "Nginx configured atomically for ${cfg[DOMAIN]}"
host_info "Nginx rollback snapshot: ${backup_dir}"
