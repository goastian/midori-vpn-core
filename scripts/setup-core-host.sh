#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"
VHOST_TEMPLATE="${REPO_ROOT}/deploy/nginx/core-vhost.conf.template"
STREAM_TEMPLATE="${REPO_ROOT}/deploy/nginx/core-stream.conf.template"
TEMP_DIR=""

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_value() {
  local name="$1"
  [ -n "${!name:-}" ] || die "missing required environment variable: ${name}"
}

require_port() {
  local name="$1"
  local value="${!name:-}"
  [[ "${value}" =~ ^[0-9]+$ ]] || die "${name} must be an integer TCP port"
  [ "${value}" -ge 1 ] && [ "${value}" -le 65535 ] || die "${name} must be between 1 and 65535"
}

require_bool() {
  local name="$1"
  case "${!name:-}" in
    true|false) ;;
    *) die "${name} must be true or false" ;;
  esac
}

sed_escape() {
  printf '%s' "$1" | sed 's/[&|]/\\&/g'
}

render_vhost() {
  local output="$1"
  sed \
    -e "s|__DOMAIN__|$(sed_escape "${DOMAIN}")|g" \
    -e "s|__VPN_CORE_HOST_PORT__|$(sed_escape "${VPN_CORE_HOST_PORT}")|g" \
    -e "s|__ACME_WEBROOT__|$(sed_escape "${ACME_WEBROOT}")|g" \
    -e "s|__CONTROL_WEB_PORT__|$(sed_escape "${CONTROL_HOST_PORT}")|g" \
    "${VHOST_TEMPLATE}" > "${output}"
}

render_stream_vhost() {
  local output="$1"
  sed \
    -e "s|__DOMAIN__|$(sed_escape "${DOMAIN}")|g" \
    -e "s|__PROXY_HOST_PORT__|$(sed_escape "${PROXY_HOST_PORT}")|g" \
    -e "s|__PROXY_PUBLIC_PORT__|$(sed_escape "${PROXY_PORT}")|g" \
    "${STREAM_TEMPLATE}" > "${output}"
}

install_rendered_file() {
  local source="$1"
  local destination="$2"
  local backup

  install -d -m 0755 "$(dirname "${destination}")"
  if [ -f "${destination}" ]; then
    backup="${destination}.pre-midori-$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "${destination}" "${backup}"
    printf 'backup=%s\n' "${backup}"
  fi
  install -m 0644 "${source}" "${destination}"
}

cleanup() {
  if [ -n "${TEMP_DIR}" ] && [ -d "${TEMP_DIR}" ]; then
    rm -rf -- "${TEMP_DIR}"
  fi
}

main() {
  [ "$(id -u)" -eq 0 ] || die "run with sudo; only host Nginx and Certbot need root, Podman services remain rootless"
  [ -f "${ENV_FILE}" ] || die "environment file not found: ${ENV_FILE}"
  [ -f "${VHOST_TEMPLATE}" ] || die "missing Nginx template: ${VHOST_TEMPLATE}"
  [ -f "${STREAM_TEMPLATE}" ] || die "missing Nginx stream template: ${STREAM_TEMPLATE}"

  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a

  for name in DOMAIN VPN_CORE_HOST_PORT CONTROL_HOST_PORT ACME_WEBROOT \
    NGINX_VHOST_PATH CERTBOT_EMAIL LETSENCRYPT_STAGING PROXY_ENABLED; do
    require_value "${name}"
  done
  require_port VPN_CORE_HOST_PORT
  require_port CONTROL_HOST_PORT
  require_bool LETSENCRYPT_STAGING
  require_bool PROXY_ENABLED
  [[ "${DOMAIN}" =~ ^[A-Za-z0-9.-]+$ ]] || die "DOMAIN contains invalid characters"
  [[ "${ACME_WEBROOT}" = /* ]] || die "ACME_WEBROOT must be an absolute path"
  [[ "${NGINX_VHOST_PATH}" = /* ]] || die "NGINX_VHOST_PATH must be an absolute path"

  if [ "${PROXY_ENABLED}" = "true" ]; then
    for name in NGINX_STREAM_VHOST_PATH PROXY_HOST_PORT PROXY_PORT; do
      require_value "${name}"
    done
    require_port PROXY_HOST_PORT
    require_port PROXY_PORT
    [[ "${NGINX_STREAM_VHOST_PATH}" = /* ]] || die "NGINX_STREAM_VHOST_PATH must be an absolute path"
  fi

  require_command certbot
  require_command nginx
  require_command sed
  require_command systemctl

  local vhost_tmp stream_tmp
  TEMP_DIR="$(mktemp -d)"
  trap cleanup EXIT
  vhost_tmp="${TEMP_DIR}/core-vhost.conf"
  render_vhost "${vhost_tmp}"
  install -d -m 0755 "${ACME_WEBROOT}/.well-known/acme-challenge"
  install_rendered_file "${vhost_tmp}" "${NGINX_VHOST_PATH}"

  if [ "${PROXY_ENABLED}" = "true" ]; then
    stream_tmp="${TEMP_DIR}/core-stream.conf"
    render_stream_vhost "${stream_tmp}"
    install_rendered_file "${stream_tmp}" "${NGINX_STREAM_VHOST_PATH}"
  fi

  nginx -t

  local certbot_args=()
  if [ "${LETSENCRYPT_STAGING}" = "true" ]; then
    certbot_args+=(--staging)
  fi
  certbot --nginx \
    --domain "${DOMAIN}" \
    --email "${CERTBOT_EMAIL}" \
    --non-interactive \
    --agree-tos \
    --redirect \
    --keep-until-expiring \
    "${certbot_args[@]}"

  nginx -t
  systemctl reload nginx
  printf 'Nginx and TLS configuration validated for %s.\n' "${DOMAIN}"
  printf 'Start the rootless services with scripts/deploy-pod.sh or the installed user Quadlets.\n'
}

main "$@"
