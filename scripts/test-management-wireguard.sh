#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-management-wg.XXXXXX")"
cleanup() { rm -rf -- "${test_root}"; }
trap cleanup EXIT
stub_dir="${test_root}/bin"
install -d -m 0700 "${stub_dir}"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

cat > "${stub_dir}/wg" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  genkey) printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' ;;
  pubkey) cat >/dev/null; printf 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n' ;;
  genpsk) printf 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\n' ;;
  show) printf 'peer\t%s\n' "$(date +%s)" ;;
  *) exit 1 ;;
esac
EOF
cat > "${stub_dir}/firewall-cmd" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> '${test_root}/firewall.log'
case "\$*" in
  *--get-zones*)
    printf 'public'
    [[ ! -f '${test_root}/zone-created' ]] || printf ' midorivpn-management'
    printf '\n'
    ;;
  *--new-zone=*) touch '${test_root}/zone-created' ;;
  *--query-port=*) exit 1 ;;
esac
EOF
cat > "${stub_dir}/systemctl" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> '${test_root}/systemctl.log'
exit 0
EOF
cat > "${stub_dir}/ip" <<'EOF'
#!/usr/bin/env bash
printf '    inet 10.254.240.1/32 scope global mvpn-mgmt\n'
EOF
cat > "${stub_dir}/ping" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod 0700 "${stub_dir}"/*

[[ ! -e /etc/wireguard/mvpn-mgmt && ! -e /etc/wireguard/mvpn-mgmt.conf ]] || fail 'container fixture is not clean'
PATH="${stub_dir}:${PATH}" bash "${ROOT}/deploy/host/configure-management-wireguard.sh" --prepare --role principal >/dev/null
printf 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\n' > "${test_root}/peer-public.key"
chmod 0600 "${test_root}/peer-public.key"

PATH="${stub_dir}:${PATH}" bash "${ROOT}/deploy/host/configure-management-wireguard.sh" \
  --apply --role principal --listen-port 55123 --endpoint 203.0.113.10:55123 \
  --peer-public-key-file "${test_root}/peer-public.key" \
  --preshared-key-file /etc/wireguard/mvpn-mgmt/preshared.key >/dev/null

grep -Fqx 'Address = 10.254.240.1/32' /etc/wireguard/mvpn-mgmt.conf || fail 'principal address missing'
grep -Fqx 'AllowedIPs = 10.254.240.2/32' /etc/wireguard/mvpn-mgmt.conf || fail 'peer route is not exact'
grep -Fqx 'Endpoint = 203.0.113.10:55123' /etc/wireguard/mvpn-mgmt.conf || fail 'endpoint missing'
grep -Fqx 'PersistentKeepalive = 25' /etc/wireguard/mvpn-mgmt.conf || fail 'keepalive missing'
if grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0/0|10[.]254[.]240[.]0/24)($|[[:space:]])' /etc/wireguard/mvpn-mgmt.conf; then
  fail 'management config contains a broad route'
fi

# Reapplying the exact same declared state converges without replacing keys or
# confusing the dedicated firewalld zone with foreign state.
PATH="${stub_dir}:${PATH}" bash "${ROOT}/deploy/host/configure-management-wireguard.sh" \
  --apply --role principal --listen-port 55123 --endpoint 203.0.113.10:55123 \
  --peer-public-key-file "${test_root}/peer-public.key" \
  --preshared-key-file /etc/wireguard/mvpn-mgmt/preshared.key >/dev/null

PATH="${stub_dir}:${PATH}" bash "${ROOT}/deploy/host/configure-management-wireguard.sh" --check --role principal >/dev/null
PATH="${stub_dir}:${PATH}" bash "${ROOT}/deploy/host/rollback-management-wireguard.sh" principal 55123 public >/dev/null
[[ ! -e /etc/wireguard/mvpn-mgmt.conf ]] || fail 'rollback retained active configuration'
[[ -f /etc/wireguard/mvpn-mgmt/private.key ]] || fail 'rollback destroyed retained identity'
grep -Fq -- '--add-interface=mvpn-mgmt' "${test_root}/firewall.log" || fail 'management firewalld binding missing'
grep -Fq -- '--add-port=8443/tcp' "${test_root}/firewall.log" || fail 'management TLS rule missing'

printf 'Management WireGuard tests passed.\n'
