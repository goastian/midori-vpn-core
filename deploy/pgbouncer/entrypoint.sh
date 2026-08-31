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

for variable_name in POSTGRES_HOST POSTGRES_PORT POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD; do
  require_value "$variable_name"
done

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
case "$POSTGRES_USER" in
  *[!A-Za-z0-9_]*|'') die 'POSTGRES_USER must be a simple PostgreSQL identifier' ;;
esac
case "$(printf '%s' "$POSTGRES_PASSWORD" | od -An -tx1)" in
  *' 0a'*|*' 0d'*) die 'POSTGRES_PASSWORD must not contain line breaks' ;;
esac

runtime_dir=/run/pgbouncer/private
install -d -m 0700 "$runtime_dir"
sed \
  -e "s/__POSTGRES_HOST__/$POSTGRES_HOST/g" \
  -e "s/__POSTGRES_PORT__/$POSTGRES_PORT/g" \
  -e "s/__POSTGRES_DB__/$POSTGRES_DB/g" \
  -e "s/__POSTGRES_USER__/$POSTGRES_USER/g" \
  /usr/share/midorivpn/pgbouncer.ini.template > "$runtime_dir/pgbouncer.ini"

escaped_password=$(printf '%s' "$POSTGRES_PASSWORD" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf '"%s" "%s"\n' "$POSTGRES_USER" "$escaped_password" > "$runtime_dir/userlist.txt"
chmod 0600 "$runtime_dir/pgbouncer.ini" "$runtime_dir/userlist.txt"

exec pgbouncer "$runtime_dir/pgbouncer.ini"
