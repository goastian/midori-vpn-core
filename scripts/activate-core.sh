#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[[ $# == 4 ]] || die "usage: bash scripts/activate-core.sh CLUSTER_UUID NODE_UUID SERVER_UUID PROTOCOL"
for id in "$1" "$2" "$3"; do
  [[ "$id" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] || die "cluster, node and server must be UUIDs"
done
case "$4" in
  wireguard|masque|wss|proxy|openvpn|ikev2) ;;
  *) die "protocol must be wireguard, masque, wss, proxy, openvpn or ikev2" ;;
esac
command -v podman >/dev/null 2>&1 || die "podman is required"
: "${POSTGRES_CONTAINER:?POSTGRES_CONTAINER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_MIGRATOR_USER:?POSTGRES_MIGRATOR_USER is required}"
: "${POSTGRES_MIGRATOR_PASSWORD:?POSTGRES_MIGRATOR_PASSWORD is required}"
for name in POSTGRES_DB POSTGRES_MIGRATOR_USER; do
  [[ "${!name}" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] || die "$name must be a simple PostgreSQL identifier"
done
[[ "$POSTGRES_MIGRATOR_PASSWORD" != *$'\n'* && "$POSTGRES_MIGRATOR_PASSWORD" != *$'\r'* ]] || die "migrator password must not contain line breaks"
podman container exists "$POSTGRES_CONTAINER" || die "PostgreSQL container does not exist"

# Use the database container's psql and direct private TCP/SCRAM, not PgBouncer
# or a local trust socket. Keep the password out of process arguments/logs.
password_file="$(mktemp "${TMPDIR:-/tmp}/midorivpn-activate.XXXXXX")"
cleanup() { rm -f -- "$password_file"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'PGPASSWORD=%s\n' "$POSTGRES_MIGRATOR_PASSWORD" >"$password_file"
{
  cat <<'SQL'
SELECT set_config('midorivpn.activation.cluster_id', :'cluster_id', false) AS cluster_setting,
       set_config('midorivpn.activation.node_id', :'node_id', false) AS node_setting,
       set_config('midorivpn.activation.server_id', :'server_id', false) AS server_setting,
       set_config('midorivpn.activation.protocol', :'protocol', false) AS protocol_setting,
       set_config('midorivpn.activation.migrator_role', :'migrator_role', false) AS migrator_setting \gset
SQL
  cat "${ROOT_DIR}/deploy/postgres/activate-core.sql"
} | podman exec -i --env-file "$password_file" "$POSTGRES_CONTAINER" \
  psql -X --no-password --quiet --set=ON_ERROR_STOP=1 \
  --host=127.0.0.1 --port=5432 --username="$POSTGRES_MIGRATOR_USER" --dbname="$POSTGRES_DB" \
  --set=cluster_id="$1" --set=node_id="$2" --set=server_id="$3" \
  --set=protocol="$4" --set=migrator_role="$POSTGRES_MIGRATOR_USER" --file=-

printf 'Activated cluster %s / node %s / server %s; %s placement gate passed.\n' "$1" "$2" "$3" "$4"
