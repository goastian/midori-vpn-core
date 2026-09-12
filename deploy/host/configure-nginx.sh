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
backup_record=""

usage() {
  printf 'usage: %s --env-file PATH [--issue-certificate] [--backup-root PATH] [--backup-record FILE]\n' "$0"
}

while (($#)); do
  case "$1" in
    --env-file) env_file="${2:-}"; shift 2 ;;
    --issue-certificate) issue_certificate=true; shift ;;
    --backup-root) backup_root="${2:-}"; shift 2 ;;
    --backup-record) backup_record="${2:-}"; shift 2 ;;
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
for key in DEPLOYMENT_PROFILE DOMAIN VPN_CORE_HOST_PORT ACME_WEBROOT NGINX_VHOST_PATH PROXY_ENABLED MANAGEMENT_HOST_BIND MANAGEMENT_HTTPS_PORT MANAGEMENT_TLS_CERT MANAGEMENT_TLS_KEY MANAGEMENT_TLS_CA; do
  host_require_env cfg "${key}"
done
[[ "${cfg[DEPLOYMENT_PROFILE]}" == principal || "${cfg[DEPLOYMENT_PROFILE]}" == core-node ]] || host_die "DEPLOYMENT_PROFILE must be principal or core-node"
[[ "${cfg[DOMAIN]}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || host_die "DOMAIN is not a valid hostname"
port_keys=(VPN_CORE_HOST_PORT)
port_keys+=(MANAGEMENT_HTTPS_PORT)
if [[ "${cfg[DEPLOYMENT_PROFILE]}" == principal ]]; then
  host_require_env cfg CONTROL_HOST_PORT
  port_keys+=(CONTROL_HOST_PORT)
fi
for key in "${port_keys[@]}"; do
  if [[ ! "${cfg[${key}]}" =~ ^[0-9]+$ ]] || ((cfg[${key}] < 1 || cfg[${key}] > 65535)); then
    host_die "${key} must be a valid port"
  fi
done
[[ "${cfg[ACME_WEBROOT]}" == /* ]] || host_die "ACME_WEBROOT must be absolute"
[[ "${cfg[NGINX_VHOST_PATH]}" == /etc/nginx/* ]] || host_die "NGINX_VHOST_PATH must remain below /etc/nginx"
host_validate_absolute_path "${cfg[NGINX_VHOST_PATH]}" NGINX_VHOST_PATH
host_validate_rfc1918_ipv4 "${cfg[MANAGEMENT_HOST_BIND]}" MANAGEMENT_HOST_BIND
for key in MANAGEMENT_TLS_CERT MANAGEMENT_TLS_KEY MANAGEMENT_TLS_CA; do
  host_validate_absolute_path "${cfg[${key}]}" "${key}"
  host_require_regular_file "${cfg[${key}]}"
done
[[ "$(stat -c '%a' -- "${cfg[MANAGEMENT_TLS_KEY]}")" == 600 ]] || host_die "MANAGEMENT_TLS_KEY must have mode 0600"
[[ "${cfg[PROXY_ENABLED]}" == true || "${cfg[PROXY_ENABLED]}" == false ]] || host_die "PROXY_ENABLED must be true or false"

management_destination="$(dirname -- "${cfg[NGINX_VHOST_PATH]}")/midorivpn-management.conf"
[[ "${management_destination}" != "${cfg[NGINX_VHOST_PATH]}" ]] || host_die "management and public Nginx destinations must differ"
destinations=("${cfg[NGINX_VHOST_PATH]}" "${management_destination}")
rendered_names=(vhost management)
if [[ "${cfg[DEPLOYMENT_PROFILE]}" == principal ]]; then
  public_template="${SOURCE_ROOT}/deploy/nginx/core-vhost.conf.template"
  management_template="${SOURCE_ROOT}/deploy/nginx/principal-management.conf.template"
else
  public_template="${SOURCE_ROOT}/deploy/nginx/core-node-vhost.conf.template"
  management_template="${SOURCE_ROOT}/deploy/nginx/core-node-management.conf.template"
fi
if [[ "${cfg[PROXY_ENABLED]}" == true ]]; then
  for key in NGINX_STREAM_VHOST_PATH PROXY_HOST_PORT PROXY_PORT; do
    host_require_env cfg "${key}"
  done
  [[ "${cfg[NGINX_STREAM_VHOST_PATH]}" == /etc/nginx/* ]] || host_die "NGINX_STREAM_VHOST_PATH must remain below /etc/nginx"
  host_validate_absolute_path "${cfg[NGINX_STREAM_VHOST_PATH]}" NGINX_STREAM_VHOST_PATH
  for key in PROXY_HOST_PORT PROXY_PORT; do
    if [[ ! "${cfg[${key}]}" =~ ^[0-9]+$ ]] || ((cfg[${key}] < 1 || cfg[${key}] > 65535)); then
      host_die "${key} must be a valid port"
    fi
  done
  destinations+=("${cfg[NGINX_STREAM_VHOST_PATH]}")
  rendered_names+=(stream)
fi

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-nginx.XXXXXX")"
cleanup() { rm -rf -- "${temporary_dir}"; }
trap cleanup EXIT

escape_sed() { printf '%s' "$1" | sed 's/[&|\\]/\\&/g'; }
sed \
  -e "s|__DOMAIN__|$(escape_sed "${cfg[DOMAIN]}")|g" \
  -e "s|__VPN_CORE_HOST_PORT__|$(escape_sed "${cfg[VPN_CORE_HOST_PORT]}")|g" \
  -e "s|__CONTROL_WEB_PORT__|$(escape_sed "${cfg[CONTROL_HOST_PORT]:-}")|g" \
  "${public_template}" > "${temporary_dir}/vhost.conf"
grep -Fq 'location = /.well-known/midorivpn/edge-health' "${temporary_dir}/vhost.conf" || host_die "rendered Nginx vhost lacks the exact edge-health route"
if grep -Eq '__[A-Z0-9_]+__' "${temporary_dir}/vhost.conf"; then
  host_die "rendered Nginx vhost contains unresolved placeholders"
fi

sed \
  -e "s|__MANAGEMENT_HOST_BIND__|$(escape_sed "${cfg[MANAGEMENT_HOST_BIND]}")|g" \
  -e "s|__MANAGEMENT_HTTPS_PORT__|$(escape_sed "${cfg[MANAGEMENT_HTTPS_PORT]}")|g" \
  -e "s|__MANAGEMENT_TLS_CERT__|$(escape_sed "${cfg[MANAGEMENT_TLS_CERT]}")|g" \
  -e "s|__MANAGEMENT_TLS_KEY__|$(escape_sed "${cfg[MANAGEMENT_TLS_KEY]}")|g" \
  -e "s|__VPN_CORE_HOST_PORT__|$(escape_sed "${cfg[VPN_CORE_HOST_PORT]}")|g" \
  "${management_template}" > "${temporary_dir}/management.conf"
if grep -Eq '__[A-Z0-9_]+__' "${temporary_dir}/management.conf"; then
  host_die "rendered Nginx management config contains unresolved placeholders"
fi

if [[ "${cfg[PROXY_ENABLED]}" == true ]]; then
  sed \
    -e "s|__DOMAIN__|$(escape_sed "${cfg[DOMAIN]}")|g" \
    -e "s|__PROXY_HOST_PORT__|$(escape_sed "${cfg[PROXY_HOST_PORT]}")|g" \
    -e "s|__PROXY_PUBLIC_PORT__|$(escape_sed "${cfg[PROXY_PORT]}")|g" \
    "${SOURCE_ROOT}/deploy/nginx/core-stream.conf.template" > "${temporary_dir}/stream.conf"
  if grep -Eq '__[A-Z0-9_]+__' "${temporary_dir}/stream.conf"; then
    host_die "rendered Nginx stream config contains unresolved placeholders"
  fi
fi

install -d -m 0700 -- "${backup_root}"
backup_dir="$(mktemp -d "${backup_root}/$(host_timestamp).XXXXXX")"
: > "${backup_dir}/targets.tsv"
chmod 0600 "${backup_dir}/targets.tsv"
if [[ -n "${backup_record}" ]]; then
  [[ "${backup_record}" == /* ]] || host_die "--backup-record must be absolute"
  install -d -m 0700 -- "$(dirname -- "${backup_record}")"
  printf '%s\n' "${backup_dir}" > "${backup_record}"
  chmod 0600 "${backup_record}"
fi
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
    printf '%s\tpresent\t%s.conf\n' "${nginx_destination}" "${index}" >> "${backup_dir}/targets.tsv"
  else
    : > "${backup_dir}/${index}.absent"
    chmod 0600 "${backup_dir}/${index}.absent"
    printf '%s\tabsent\t%s.absent\n' "${nginx_destination}" "${index}" >> "${backup_dir}/targets.tsv"
  fi
  rendered_name="${rendered_names[${index}]}"
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
