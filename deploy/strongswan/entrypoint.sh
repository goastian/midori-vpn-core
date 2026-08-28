#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_value() {
  local name="$1"
  [ -n "${!name:-}" ] || die "missing required environment variable: ${name}"
}

valid_ipv4() {
  local address="$1" octet
  [[ "${address}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<<"${address}"
  for octet in "${octets[@]}"; do
    [ "${octet}" -ge 0 ] && [ "${octet}" -le 255 ] || return 1
  done
}

sed_escape() {
  printf '%s' "$1" | sed 's/[&|]/\\&/g'
}

for name in IKEV2_SERVER_NAME IKEV2_NETWORK_CIDR VPN_DNS VPN_CLIENT_CRL_URL; do
  require_value "${name}"
done
IKEV2_PORT="${IKEV2_PORT:-500}"
IKEV2_NAT_T_PORT="${IKEV2_NAT_T_PORT:-4500}"
IKEV2_CA_CERT="${IKEV2_CA_CERT:-/etc/midorivpn/pki/client-ca.pem}"
IKEV2_GATEWAY_CERT="${IKEV2_GATEWAY_CERT:-/etc/midorivpn/pki/gateway.crt}"
IKEV2_GATEWAY_KEY="${IKEV2_GATEWAY_KEY:-/etc/midorivpn/pki/gateway.key}"
IKEV2_RUNTIME_DIR="/run/midorivpn-ikev2"
IKEV2_HEALTH_BINARY="${IKEV2_HEALTH_BINARY:-/usr/local/libexec/midorivpn-ikev2-health}"
IKEV2_HEALTH_FILE="/run/midorivpn-health/ikev2.json"
IKEV2_SWANCTL_CONFIG="${IKEV2_RUNTIME_DIR}/swanctl/swanctl.conf"
[[ "${IKEV2_PORT}" =~ ^[0-9]+$ ]] && [ "${IKEV2_PORT}" -ge 1 ] && [ "${IKEV2_PORT}" -le 65535 ] || die "invalid IKEV2_PORT"
[[ "${IKEV2_NAT_T_PORT}" =~ ^[0-9]+$ ]] && [ "${IKEV2_NAT_T_PORT}" -ge 1 ] && [ "${IKEV2_NAT_T_PORT}" -le 65535 ] || die "invalid IKEV2_NAT_T_PORT"
valid_ipv4 "${VPN_DNS}" || die "invalid VPN_DNS"
[[ "${IKEV2_NETWORK_CIDR}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-9]|[12][0-9]|30)$ ]] || die "invalid IKEV2_NETWORK_CIDR"
valid_ipv4 "${IKEV2_NETWORK_CIDR%/*}" || die "invalid IKEV2_NETWORK_CIDR address"
[[ "${VPN_CLIENT_CRL_URL}" == https://* ]] || die "VPN_CLIENT_CRL_URL must use https"
[[ "${IKEV2_SERVER_NAME}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "invalid IKEV2_SERVER_NAME"

for file in "${IKEV2_CA_CERT}" "${IKEV2_GATEWAY_CERT}" "${IKEV2_GATEWAY_KEY}"; do
  [ -r "${file}" ] || die "required PKI file is not readable: ${file}"
done
openssl x509 -in "${IKEV2_GATEWAY_CERT}" -noout -checkend 86400 >/dev/null || die "gateway certificate expires within 24 hours"
openssl verify -purpose sslserver -verify_hostname "${IKEV2_SERVER_NAME}" -CAfile "${IKEV2_CA_CERT}" "${IKEV2_GATEWAY_CERT}" >/dev/null || die "gateway certificate verification failed"

install -d -m 0700 "${IKEV2_RUNTIME_DIR}" \
  "${IKEV2_RUNTIME_DIR}"/swanctl/{ecdsa,pkcs8,pkcs12,private,pubkey,rsa,x509,x509aa,x509ac,x509ca,x509crl,x509ocsp}
install -d -m 0755 /run/midorivpn-health
rm -f "${IKEV2_HEALTH_FILE}" /run/midorivpn-health/ikev2.sock
install -m 0600 "${IKEV2_GATEWAY_KEY}" "${IKEV2_RUNTIME_DIR}/swanctl/private/gateway.key"
install -m 0644 "${IKEV2_GATEWAY_CERT}" "${IKEV2_RUNTIME_DIR}/swanctl/x509/gateway.crt"
install -m 0644 "${IKEV2_CA_CERT}" "${IKEV2_RUNTIME_DIR}/swanctl/x509ca/client-ca.pem"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 "${VPN_CLIENT_CRL_URL}" -o "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.der"
openssl crl -inform DER -in "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.der" -out "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next" -outform PEM || die "initial client CRL encoding is invalid"
openssl crl -in "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next" -CAfile "${IKEV2_CA_CERT}" -noout -verify >/dev/null || die "initial client CRL verification failed"
chmod 0644 "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next"
mv "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next" "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl"
rm -f "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.der"

sed \
  -e "s|__IKE_PORT__|$(sed_escape "${IKEV2_PORT}")|g" \
  -e "s|__NAT_T_PORT__|$(sed_escape "${IKEV2_NAT_T_PORT}")|g" \
  /usr/share/midorivpn/strongswan/strongswan.conf.template >"${IKEV2_RUNTIME_DIR}/strongswan.conf"
sed \
  -e "s|__SERVER_NAME__|$(sed_escape "${IKEV2_SERVER_NAME}")|g" \
  -e "s|__NETWORK_CIDR__|$(sed_escape "${IKEV2_NETWORK_CIDR}")|g" \
  -e "s|__DNS__|$(sed_escape "${VPN_DNS}")|g" \
  /usr/share/midorivpn/strongswan/swanctl.conf.template >"${IKEV2_SWANCTL_CONFIG}"
chmod 0600 "${IKEV2_RUNTIME_DIR}/strongswan.conf" "${IKEV2_SWANCTL_CONFIG}"

[ "$(sysctl -n net.ipv4.ip_forward)" = "1" ] || die "execution network namespace must start with net.ipv4.ip_forward=1"
nft delete table ip midori_ikev2 2>/dev/null || true
nft add table ip midori_ikev2
nft 'add chain ip midori_ikev2 postrouting { type nat hook postrouting priority srcnat; policy accept; }'
nft add rule ip midori_ikev2 postrouting ip saddr "${IKEV2_NETWORK_CIDR}" masquerade

refresh_crl() {
  while sleep 60; do
    if curl --fail --silent --show-error --proto '=https' --tlsv1.2 "${VPN_CLIENT_CRL_URL}" -o "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.der" && \
      openssl crl -inform DER -in "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.der" -out "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next" -outform PEM && \
      openssl crl -in "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next" -CAfile "${IKEV2_CA_CERT}" -noout -verify >/dev/null; then
      chmod 0644 "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next"
      mv "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next" "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl"
      STRONGSWAN_CONF="${IKEV2_RUNTIME_DIR}/strongswan.conf" /usr/sbin/swanctl --load-creds --file "${IKEV2_SWANCTL_CONFIG}" --uri "unix://${IKEV2_RUNTIME_DIR}/charon.vici" >/dev/null || true
    else
      rm -f "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.der" "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.next"
      printf 'warning: rejected client CRL refresh\n' >&2
    fi
    rm -f "${IKEV2_RUNTIME_DIR}/swanctl/x509crl/client.crl.der"
  done
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  [ -z "${health_pid:-}" ] || kill "${health_pid}" 2>/dev/null || true
  [ -z "${refresh_pid:-}" ] || kill "${refresh_pid}" 2>/dev/null || true
  [ -z "${charon_pid:-}" ] || kill "${charon_pid}" 2>/dev/null || true
  wait 2>/dev/null || true
  exit "${status}"
}
trap cleanup EXIT INT TERM

STRONGSWAN_CONF="${IKEV2_RUNTIME_DIR}/strongswan.conf" /usr/libexec/ipsec/charon &
charon_pid=$!
for _ in $(seq 1 50); do
  [ -S "${IKEV2_RUNTIME_DIR}/charon.vici" ] && break
  kill -0 "${charon_pid}" 2>/dev/null || die "strongSwan charon exited during startup"
  sleep 0.1
done
[ -S "${IKEV2_RUNTIME_DIR}/charon.vici" ] || die "strongSwan VICI socket was not created"
STRONGSWAN_CONF="${IKEV2_RUNTIME_DIR}/strongswan.conf" /usr/sbin/swanctl --load-all --file "${IKEV2_SWANCTL_CONFIG}" --uri "unix://${IKEV2_RUNTIME_DIR}/charon.vici"

export IKEV2_VICI_SOCKET="${IKEV2_RUNTIME_DIR}/charon.vici"
export IKEV2_CONNECTION_NAME=midori-ikev2
export IKEV2_HEALTH_FILE
refresh_crl &
refresh_pid=$!
"${IKEV2_HEALTH_BINARY}" &
health_pid=$!
while kill -0 "${charon_pid}" 2>/dev/null && kill -0 "${health_pid}" 2>/dev/null && kill -0 "${refresh_pid}" 2>/dev/null; do
  sleep 1
done
if kill -0 "${charon_pid}" 2>/dev/null; then
  die "IKEv2 gateway helper exited unexpectedly"
fi
wait "${charon_pid}"
