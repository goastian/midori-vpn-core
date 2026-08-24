#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="${1:?usage: migrate-node-auth-env.sh ENV_FILE SOURCE_DIR NODE_ID}"
SOURCE_DIR="${2:?usage: migrate-node-auth-env.sh ENV_FILE SOURCE_DIR NODE_ID}"
NODE_ID="${3:?usage: migrate-node-auth-env.sh ENV_FILE SOURCE_DIR NODE_ID}"

[ -f "$ENV_FILE" ] || { printf 'error: environment file not found: %s\n' "$ENV_FILE" >&2; exit 1; }
[ -f "$SOURCE_DIR/cmd/node-keygen/main.go" ] || { printf 'error: node-keygen source not found under %s\n' "$SOURCE_DIR" >&2; exit 1; }
command -v podman >/dev/null 2>&1 || { printf 'error: podman is required\n' >&2; exit 1; }

umask 077
identity="$({
  podman run --rm --userns=keep-id:uid=0,gid=0 \
    -v "$SOURCE_DIR:/workspace:ro,Z" \
    -w /workspace \
    docker.io/library/golang:1.27-alpine \
    go run ./cmd/node-keygen
} 2>/dev/null)"

private_key="$(printf '%s\n' "$identity" | sed -n 's/^CONTROL_NODE_PRIVATE_KEY=//p')"
public_key="$(printf '%s\n' "$identity" | sed -n 's/^CONTROL_NODE_PUBLIC_KEY=//p')"
credential_secret="$(printf '%s\n' "$identity" | sed -n 's/^CREDENTIAL_SIGNING_SECRET=//p')"
redis_url="$(sed -n 's/^REDIS_URL=//p' "$ENV_FILE" | tail -n 1)"

for value in "$private_key" "$public_key" "$credential_secret" "$redis_url"; do
  [ -n "$value" ] || { printf 'error: could not derive required node-auth configuration\n' >&2; exit 1; }
done

backup="${ENV_FILE}.pre-ed25519.$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$ENV_FILE" "$backup"
tmp="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

awk -F= '
  $1 != "VPN_CORE_TOKEN" &&
  $1 != "CONTROL_NODE_ID" &&
  $1 != "CONTROL_NODE_PRIVATE_KEY" &&
  $1 != "NODE_AUTHORIZED_KEYS" &&
  $1 != "NODE_REVOKED_IDS" &&
  $1 != "NODE_AUTH_REDIS_URL" &&
  $1 != "CREDENTIAL_SIGNING_SECRET" &&
  $1 != "OAUTH_ALLOWED_REDIRECT_URIS" { print }
' "$ENV_FILE" > "$tmp"

{
  printf '\n# Ed25519 signed Control-to-Core requests\n'
  printf 'CONTROL_NODE_ID=%s\n' "$NODE_ID"
  printf 'CONTROL_NODE_PRIVATE_KEY=%s\n' "$private_key"
  printf 'NODE_AUTHORIZED_KEYS=%s=%s\n' "$NODE_ID" "$public_key"
  printf 'NODE_REVOKED_IDS=\n'
  printf 'NODE_AUTH_REDIS_URL=%s\n' "$redis_url"
  printf 'CREDENTIAL_SIGNING_SECRET=%s\n' "$credential_secret"
  printf 'OAUTH_ALLOWED_REDIRECT_URIS=http://127.0.0.1:7071/oauth/callback\n'
} >> "$tmp"

chmod --reference="$ENV_FILE" "$tmp"
mv "$tmp" "$ENV_FILE"
trap - EXIT
printf 'Node authentication configuration migrated. Backup: %s\n' "$backup"
