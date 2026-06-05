#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
TEMPLATE="$REPO_ROOT/deploy/nginx/core-vhost.conf.template"
STREAM_TEMPLATE="$REPO_ROOT/deploy/nginx/core-stream.conf.template"
ACME_WEBROOT="/var/www/certbot"
VHOST_NAME="midori-vpn-core.conf"
STREAM_VHOST_NAME="midori-vpn-core-stream.conf"

DOMAIN=""
VPN_CORE_HOST_PORT="8085"
VPN_CORE_TOKEN=""
WG_ENDPOINT=""
WG_PORT="51820"
POSTGRES_USER="midori"
POSTGRES_PASSWORD=""
POSTGRES_DB="midori_vpn"
REDIS_PASSWORD=""
CORE_ALLOWED_HOSTS=""
TRUSTED_PROXIES="172.16.0.0/12"
PROXY_ENABLED="false"
PROXY_PORT="8888"
PROXY_HOST_PORT="18888"
LETSENCRYPT_STAGING="true"

NGINX_MODE=""
NGINX_VHOST_PATH=""
NGINX_ENABLED_PATH=""
NGINX_RELOAD_CMD=""

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '%s\n' "$*"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "run this script with sudo so it can write nginx and certbot files"
  fi
}

prompt() {
  local label="$1"
  local default_value="${2:-}"
  local value

  if [ -n "$default_value" ]; then
    read -r -p "$label [$default_value]: " value
    printf '%s' "${value:-$default_value}"
  else
    read -r -p "$label: " value
    printf '%s' "$value"
  fi
}

prompt_required() {
  local label="$1"
  local default_value="${2:-}"
  local value

  while true; do
    value="$(prompt "$label" "$default_value")"
    if [ -n "$value" ]; then
      printf '%s' "$value"
      return
    fi
    info "Value is required."
  done
}

prompt_bool() {
  local label="$1"
  local default_value="$2"
  local value

  while true; do
    value="$(prompt "$label (true/false)" "$default_value")"
    case "$value" in
      true|false)
        printf '%s' "$value"
        return
        ;;
      *)
        info "Use true or false."
        ;;
    esac
  done
}

confirm() {
  local label="$1"
  local value

  read -r -p "$label [y/N]: " value
  case "$value" in
    y|Y|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
    return
  fi
  { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 64; } || true
  printf '\n'
}

detect_os() {
  OS_ID=""
  OS_ID_LIKE=""
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_ID_LIKE="${ID_LIKE:-}"
  fi
}

os_matches() {
  local needle="$1"
  case " $OS_ID $OS_ID_LIKE " in
    *" $needle "*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

certbot_install_hint() {
  detect_os
  info "certbot is not installed. Install it first, then rerun this script."
  if os_matches debian || os_matches ubuntu; then
    info "Suggested command: sudo apt update && sudo apt install -y certbot"
  elif os_matches opensuse || os_matches suse; then
    info "Suggested command: sudo zypper install certbot"
  elif os_matches fedora || os_matches rhel || os_matches centos; then
    info "Suggested command: sudo dnf install certbot"
  else
    info "Install the certbot package for your OS package manager."
  fi
}

detect_nginx_paths() {
  detect_os

  if os_matches debian || os_matches ubuntu; then
    if [ -d /etc/nginx/sites-available ] && [ -d /etc/nginx/sites-enabled ]; then
      NGINX_MODE="sites"
      NGINX_VHOST_PATH="/etc/nginx/sites-available/$VHOST_NAME"
      NGINX_ENABLED_PATH="/etc/nginx/sites-enabled/$VHOST_NAME"
      return
    fi
  fi

  if [ -d /etc/nginx/conf.d ]; then
    NGINX_MODE="conf.d"
    NGINX_VHOST_PATH="/etc/nginx/conf.d/$VHOST_NAME"
    NGINX_ENABLED_PATH=""
    return
  fi

  NGINX_MODE="custom"
  NGINX_VHOST_PATH="$(prompt_required "Nginx vhost file path" "/etc/nginx/conf.d/$VHOST_NAME")"
  NGINX_ENABLED_PATH=""
}

detect_reload_cmd() {
  if command -v systemctl >/dev/null 2>&1; then
    NGINX_RELOAD_CMD="systemctl reload nginx"
    return
  fi
  NGINX_RELOAD_CMD="nginx -s reload"
}

nginx_test() {
  nginx -t
}

nginx_reload() {
  sh -c "$NGINX_RELOAD_CMD"
}

activate_vhost() {
  if [ "$NGINX_MODE" = "sites" ]; then
    ln -sfn "$NGINX_VHOST_PATH" "$NGINX_ENABLED_PATH"
  fi
}

sed_escape() {
  printf '%s' "$1" | sed 's/[&|]/\\&/g'
}

render_final_vhost() {
  local domain host_port webroot
  domain="$(sed_escape "$DOMAIN")"
  host_port="$(sed_escape "$VPN_CORE_HOST_PORT")"
  webroot="$(sed_escape "$ACME_WEBROOT")"

  sed \
    -e "s|__DOMAIN__|$domain|g" \
    -e "s|__VPN_CORE_HOST_PORT__|$host_port|g" \
    -e "s|__ACME_WEBROOT__|$webroot|g" \
    "$TEMPLATE" > "$NGINX_VHOST_PATH"
}

render_stream_vhost() {
  local host_port public_port
  host_port="$(sed_escape "$PROXY_HOST_PORT")"
  public_port="$(sed_escape "$PROXY_PORT")"

  sed \
    -e "s|__PROXY_HOST_PORT__|$host_port|g" \
    -e "s|__PROXY_PUBLIC_PORT__|$public_port|g" \
    "$STREAM_TEMPLATE"
}

write_bootstrap_vhost() {
  cat > "$NGINX_VHOST_PATH" <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ {
        root $ACME_WEBROOT;
        default_type "text/plain";
        try_files \$uri =404;
    }

    location / {
        return 200 "ACME bootstrap for $DOMAIN\n";
    }
}
EOF
}

write_renew_hook() {
  local hook="/etc/letsencrypt/renewal-hooks/deploy/midori-vpn-core-nginx-reload.sh"
  install -d -m 0755 "$(dirname "$hook")"
  cat > "$hook" <<EOF
#!/bin/sh
$NGINX_RELOAD_CMD
EOF
  chmod 0755 "$hook"
}

run_certbot_if_needed() {
  local cert_path="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  local staging_args=()

  if [ -f "$cert_path" ]; then
    info "Existing certificate found for $DOMAIN; skipping initial issuance."
    return
  fi

  if [ "$LETSENCRYPT_STAGING" = "true" ]; then
    staging_args=(--staging)
  fi

  certbot certonly \
    --webroot \
    --webroot-path "$ACME_WEBROOT" \
    --domain "$DOMAIN" \
    --non-interactive \
    --agree-tos \
    --register-unsafely-without-email \
    --no-eff-email \
    --keep-until-expiring \
    --preferred-challenges http \
    --deploy-hook "$NGINX_RELOAD_CMD" \
    "${staging_args[@]}"
}

write_env_file() {
  local tmp
  tmp="$(mktemp "$REPO_ROOT/.env.tmp.XXXXXX")"
  umask 077
  cat > "$tmp" <<EOF
APP_ENV=production
DOMAIN=$DOMAIN

VPN_CORE_HOST_PORT=$VPN_CORE_HOST_PORT
VPN_CORE_PORT=8080
VPN_CORE_TOKEN=$VPN_CORE_TOKEN

WG_INTERFACE=wg0
WG_PORT=$WG_PORT
WG_SUBNET=10.8.0.0/16
WG_CONFIG_DIR=/etc/wireguard
WG_ENDPOINT=$WG_ENDPOINT

AUTHENTIK_ISSUER=
AUTHENTIK_CLIENT_ID=
AUTHENTIK_CLIENT_SECRET=
AUTHENTIK_JWKS_URL=

POSTGRES_USER=$POSTGRES_USER
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=$POSTGRES_DB
POSTGRES_SSLMODE=disable
DATABASE_URL=

REDIS_PASSWORD=$REDIS_PASSWORD
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0
REDIS_URL=

PUBLIC_BASE_URL=https://$DOMAIN
CORS_ALLOWED_ORIGINS=https://$DOMAIN

CORE_TLS_SKIP_VERIFY=false
CORE_ALLOW_INSECURE_HTTP=false
CORE_ALLOWED_HOSTS=$CORE_ALLOWED_HOSTS
TRUSTED_PROXIES=$TRUSTED_PROXIES

PROXY_ENABLED=$PROXY_ENABLED
PROXY_PORT=$PROXY_PORT
PROXY_HOST_PORT=$PROXY_HOST_PORT

LETSENCRYPT_STAGING=$LETSENCRYPT_STAGING
EOF
  mv "$tmp" "$ENV_FILE"

  if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
    chown "$SUDO_UID:$SUDO_GID" "$ENV_FILE"
  fi
}

collect_inputs() {
  DOMAIN="$(prompt_required "Core domain")"
  VPN_CORE_HOST_PORT="$(prompt_required "Host loopback port for vpn-core HTTP" "$VPN_CORE_HOST_PORT")"

  VPN_CORE_TOKEN="$(prompt "VPN_CORE_TOKEN (blank = generate)")"
  if [ -z "$VPN_CORE_TOKEN" ]; then
    VPN_CORE_TOKEN="$(generate_secret)"
    info "Generated VPN_CORE_TOKEN."
  fi

  POSTGRES_USER="$(prompt_required "PostgreSQL user" "$POSTGRES_USER")"
  POSTGRES_DB="$(prompt_required "PostgreSQL database" "$POSTGRES_DB")"
  POSTGRES_PASSWORD="$(prompt "POSTGRES_PASSWORD (blank = generate)")"
  if [ -z "$POSTGRES_PASSWORD" ]; then
    POSTGRES_PASSWORD="$(generate_secret)"
    info "Generated POSTGRES_PASSWORD."
  fi

  REDIS_PASSWORD="$(prompt "REDIS_PASSWORD (blank = generate)")"
  if [ -z "$REDIS_PASSWORD" ]; then
    REDIS_PASSWORD="$(generate_secret)"
    info "Generated REDIS_PASSWORD."
  fi

  WG_ENDPOINT="$(prompt_required "WireGuard public endpoint" "$DOMAIN")"
  WG_PORT="$(prompt_required "WireGuard UDP port" "$WG_PORT")"
  CORE_ALLOWED_HOSTS="$(prompt_required "CORE_ALLOWED_HOSTS" "$DOMAIN")"
  TRUSTED_PROXIES="$(prompt_required "TRUSTED_PROXIES" "$TRUSTED_PROXIES")"
  PROXY_ENABLED="$(prompt_bool "Enable HTTP CONNECT proxy" "$PROXY_ENABLED")"
  if [ "$PROXY_ENABLED" = "true" ]; then
    PROXY_PORT="$(prompt_required "Proxy public TCP port (extension clients)" "$PROXY_PORT")"
    PROXY_HOST_PORT="$(prompt_required "Proxy host loopback upstream port (nginx stream -> docker)" "$PROXY_HOST_PORT")"
  fi
  LETSENCRYPT_STAGING="$(prompt_bool "Use Let's Encrypt staging" "$LETSENCRYPT_STAGING")"
}

main() {
  require_root

  [ -f "$TEMPLATE" ] || die "missing nginx template: $TEMPLATE"
  [ -f "$STREAM_TEMPLATE" ] || die "missing nginx stream template: $STREAM_TEMPLATE"
  command -v nginx >/dev/null 2>&1 || die "nginx is not installed on the host"
  if ! command -v certbot >/dev/null 2>&1; then
    certbot_install_hint
    exit 1
  fi

  if [ -f "$ENV_FILE" ]; then
    confirm "$ENV_FILE already exists. Overwrite it?" || die "aborted"
  fi

  collect_inputs
  detect_nginx_paths
  detect_reload_cmd

  install -d -m 0755 "$ACME_WEBROOT/.well-known/acme-challenge"
  install -d -m 0755 "$(dirname "$NGINX_VHOST_PATH")"

  write_env_file
  write_renew_hook

  if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    info "Installing temporary HTTP-only vhost for ACME challenge."
    write_bootstrap_vhost
    activate_vhost
    nginx_test
    nginx_reload
    run_certbot_if_needed
  fi

  info "Installing final TLS vhost."
  render_final_vhost
  activate_vhost

  if [ "$PROXY_ENABLED" = "true" ]; then
    local stream_dir="/etc/nginx/stream.d"
    local stream_path="$stream_dir/$STREAM_VHOST_NAME"
    install -d -m 0755 "$stream_dir"
    render_stream_vhost > "$stream_path"
    info "Installed stream vhost at $stream_path"
    info "Ensure nginx.conf has a top-level stream include, e.g.:"
    info "  stream { include /etc/nginx/stream.d/*.conf; }"
  fi

  nginx_test
  nginx_reload

  info "Done."
  info "Start the core with: docker compose -f docker-compose-prod.yml up -d"
}

main "$@"
