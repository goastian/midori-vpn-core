#!/usr/bin/env sh
set -eu

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_value() {
  variable_name="$1"
  eval "variable_value=\${$variable_name:-}"
  [ -n "$variable_value" ] || die "$variable_name is required"
}

for variable_name in POSTGRES_HOST POSTGRES_PORT POSTGRES_DB POSTGRES_RUNTIME_USER POSTGRES_RUNTIME_PASSWORD PGBOUNCER_ADMIN_USER PGBOUNCER_ADMIN_PASSWORD; do
  require_value "$variable_name"
done

: "${PGBOUNCER_MAX_CLIENT_CONN:=200}"
: "${PGBOUNCER_DEFAULT_POOL_SIZE:=16}"
: "${PGBOUNCER_MIN_POOL_SIZE:=2}"
: "${PGBOUNCER_RESERVE_POOL_SIZE:=4}"
: "${PGBOUNCER_MAX_DB_CONNECTIONS:=24}"

case "$POSTGRES_HOST" in
  *[!A-Za-z0-9._:-]*|'') die 'POSTGRES_HOST contains invalid characters' ;;
esac
case "$POSTGRES_PORT" in
  *[!0-9]*|'') die 'POSTGRES_PORT must be numeric' ;;
esac
[ "$POSTGRES_PORT" -ge 1 ] && [ "$POSTGRES_PORT" -le 65535 ] || die 'POSTGRES_PORT is outside the valid range'
case "$POSTGRES_DB" in
  *[!A-Za-z0-9_]*|'') die 'POSTGRES_DB must be a simple PostgreSQL identifier' ;;
esac
for variable_name in POSTGRES_RUNTIME_USER PGBOUNCER_ADMIN_USER; do
  eval "variable_value=\${$variable_name}"
  case "$variable_value" in
    *[!A-Za-z0-9_]*|'') die "$variable_name must be a simple PostgreSQL identifier" ;;
  esac
done
[ "$POSTGRES_RUNTIME_USER" != "$PGBOUNCER_ADMIN_USER" ] || die 'PGBOUNCER_ADMIN_USER must differ from POSTGRES_RUNTIME_USER'
for variable_name in POSTGRES_RUNTIME_PASSWORD PGBOUNCER_ADMIN_PASSWORD; do
  eval "variable_value=\${$variable_name}"
  case "$(printf '%s' "$variable_value" | od -An -tx1)" in
    *' 0a'*|*' 0d'*) die "$variable_name must not contain line breaks" ;;
  esac
done
for variable_name in PGBOUNCER_MAX_CLIENT_CONN PGBOUNCER_DEFAULT_POOL_SIZE PGBOUNCER_MIN_POOL_SIZE PGBOUNCER_RESERVE_POOL_SIZE PGBOUNCER_MAX_DB_CONNECTIONS; do
  eval "variable_value=\${$variable_name}"
  case "$variable_value" in
    *[!0-9]*|'') die "$variable_name must be numeric" ;;
  esac
done
[ "$PGBOUNCER_MAX_CLIENT_CONN" -ge 1 ] && [ "$PGBOUNCER_MAX_CLIENT_CONN" -le 10000 ] || die 'PGBOUNCER_MAX_CLIENT_CONN is outside the valid range'
[ "$PGBOUNCER_DEFAULT_POOL_SIZE" -ge 1 ] && [ "$PGBOUNCER_DEFAULT_POOL_SIZE" -le 256 ] || die 'PGBOUNCER_DEFAULT_POOL_SIZE is outside the valid range'
[ "$PGBOUNCER_MIN_POOL_SIZE" -ge 0 ] && [ "$PGBOUNCER_MIN_POOL_SIZE" -le "$PGBOUNCER_DEFAULT_POOL_SIZE" ] || die 'PGBOUNCER_MIN_POOL_SIZE must not exceed PGBOUNCER_DEFAULT_POOL_SIZE'
[ "$PGBOUNCER_RESERVE_POOL_SIZE" -ge 0 ] && [ "$PGBOUNCER_RESERVE_POOL_SIZE" -le 256 ] || die 'PGBOUNCER_RESERVE_POOL_SIZE is outside the valid range'
[ "$PGBOUNCER_MAX_DB_CONNECTIONS" -ge "$PGBOUNCER_DEFAULT_POOL_SIZE" ] && [ "$PGBOUNCER_MAX_DB_CONNECTIONS" -le 512 ] || die 'PGBOUNCER_MAX_DB_CONNECTIONS must cover the default pool and remain at most 512'

runtime_dir=/run/pgbouncer/private
install -d -m 0700 "$runtime_dir"
sed \
  -e "s/__POSTGRES_HOST__/$POSTGRES_HOST/g" \
  -e "s/__POSTGRES_PORT__/$POSTGRES_PORT/g" \
  -e "s/__POSTGRES_DB__/$POSTGRES_DB/g" \
  -e "s/__PGBOUNCER_ADMIN_USER__/$PGBOUNCER_ADMIN_USER/g" \
  -e "s/__PGBOUNCER_MAX_CLIENT_CONN__/$PGBOUNCER_MAX_CLIENT_CONN/g" \
  -e "s/__PGBOUNCER_DEFAULT_POOL_SIZE__/$PGBOUNCER_DEFAULT_POOL_SIZE/g" \
  -e "s/__PGBOUNCER_MIN_POOL_SIZE__/$PGBOUNCER_MIN_POOL_SIZE/g" \
  -e "s/__PGBOUNCER_RESERVE_POOL_SIZE__/$PGBOUNCER_RESERVE_POOL_SIZE/g" \
  -e "s/__PGBOUNCER_MAX_DB_CONNECTIONS__/$PGBOUNCER_MAX_DB_CONNECTIONS/g" \
  /usr/share/midorivpn/pgbouncer.ini.template > "$runtime_dir/pgbouncer.ini"

runtime_password=$(printf '%s' "$POSTGRES_RUNTIME_PASSWORD" | sed 's/\\/\\\\/g; s/"/\\"/g')
admin_password=$(printf '%s' "$PGBOUNCER_ADMIN_PASSWORD" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf '"%s" "%s"\n"%s" "%s"\n' \
  "$POSTGRES_RUNTIME_USER" "$runtime_password" \
  "$PGBOUNCER_ADMIN_USER" "$admin_password" > "$runtime_dir/userlist.txt"
chmod 0600 "$runtime_dir/pgbouncer.ini" "$runtime_dir/userlist.txt"

exec pgbouncer "$runtime_dir/pgbouncer.ini"
