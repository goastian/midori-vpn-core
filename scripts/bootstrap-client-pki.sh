#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_command openssl

PKI_DIR="${PKI_DIR:-${PWD}/client-pki}"
GATEWAY_DNS_NAME="${GATEWAY_DNS_NAME:-}"
CA_DAYS="${CA_DAYS:-3650}"
GATEWAY_DAYS="${GATEWAY_DAYS:-825}"

[ -n "${GATEWAY_DNS_NAME}" ] || die "GATEWAY_DNS_NAME is required"
[[ "${GATEWAY_DNS_NAME}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || die "invalid GATEWAY_DNS_NAME"
[[ "${CA_DAYS}" =~ ^[0-9]+$ ]] && [ "${CA_DAYS}" -ge 365 ] || die "CA_DAYS must be at least 365"
[[ "${GATEWAY_DAYS}" =~ ^[0-9]+$ ]] && [ "${GATEWAY_DAYS}" -ge 30 ] && [ "${GATEWAY_DAYS}" -le "${CA_DAYS}" ] || die "GATEWAY_DAYS must be between 30 and CA_DAYS"

case "${PKI_DIR}" in
  /|"${HOME}"|"") die "refusing unsafe PKI_DIR: ${PKI_DIR}" ;;
esac

for name in client-ca.key client-ca.pem gateway.key gateway.crt; do
  [ ! -e "${PKI_DIR}/${name}" ] || die "refusing to overwrite existing PKI file: ${PKI_DIR}/${name}"
done

install -d -m 0700 "${PKI_DIR}"
temporary="$(mktemp -d "${PKI_DIR}/.bootstrap.XXXXXX")"
cleanup() {
  rm -rf -- "${temporary}"
}
trap cleanup EXIT

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${temporary}/client-ca.key"
openssl req -new -x509 -sha256 -days "${CA_DAYS}" \
  -key "${temporary}/client-ca.key" \
  -subj "/CN=MidoriVPN Device CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out "${temporary}/client-ca.pem"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${temporary}/gateway.key"
openssl req -new -sha256 -key "${temporary}/gateway.key" \
  -subj "/CN=${GATEWAY_DNS_NAME}" -out "${temporary}/gateway.csr"
cat >"${temporary}/gateway.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:${GATEWAY_DNS_NAME}
authorityKeyIdentifier=keyid,issuer
subjectKeyIdentifier=hash
EOF
openssl x509 -req -sha256 -days "${GATEWAY_DAYS}" \
  -in "${temporary}/gateway.csr" \
  -CA "${temporary}/client-ca.pem" -CAkey "${temporary}/client-ca.key" -CAcreateserial \
  -extfile "${temporary}/gateway.ext" -out "${temporary}/gateway.crt"

openssl verify -purpose sslserver -CAfile "${temporary}/client-ca.pem" "${temporary}/gateway.crt"
openssl x509 -in "${temporary}/gateway.crt" -noout -checkhost "${GATEWAY_DNS_NAME}" >/dev/null

install -m 0600 "${temporary}/client-ca.key" "${PKI_DIR}/client-ca.key"
install -m 0644 "${temporary}/client-ca.pem" "${PKI_DIR}/client-ca.pem"
install -m 0600 "${temporary}/gateway.key" "${PKI_DIR}/gateway.key"
install -m 0644 "${temporary}/gateway.crt" "${PKI_DIR}/gateway.crt"

printf 'PKI created in %s\n' "${PKI_DIR}"
printf 'Configure Core VPN_CLIENT_CA_CERT=%s and VPN_CLIENT_CA_KEY=%s\n' "${PKI_DIR}/client-ca.pem" "${PKI_DIR}/client-ca.key"
printf 'Mount gateway.crt, gateway.key and client-ca.pem read-only in the OpenVPN gateway.\n'
