#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-management-pki.XXXXXX")"
cleanup() { rm -rf -- "${test_root}"; }
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

passphrase_file="${test_root}/passphrase"
printf '%s\n' 'correct horse battery staple 2026' > "${passphrase_file}"
chmod 0600 "${passphrase_file}"
output_dir="${test_root}/pki"
bash "${ROOT}/deploy/host/generate-management-pki.sh" "${output_dir}" \
  --passphrase-file "${passphrase_file}" >/dev/null

grep -Fq 'BEGIN ENCRYPTED PRIVATE KEY' "${output_dir}/ca.key" || fail 'CA key is not encrypted'
if openssl pkey -in "${output_dir}/ca.key" -passin pass:wrong -noout >/dev/null 2>&1; then
  fail 'CA key accepted an incorrect passphrase'
fi
openssl pkey -in "${output_dir}/ca.key" -passin "file:${passphrase_file}" -noout
openssl verify -CAfile "${output_dir}/ca.crt" \
  "${output_dir}/principal.crt" "${output_dir}/regional.crt" >/dev/null
openssl x509 -in "${output_dir}/principal.crt" -noout -ext subjectAltName | grep -Fq 'IP Address:10.254.240.1' || fail 'principal SAN is incorrect'
openssl x509 -in "${output_dir}/regional.crt" -noout -ext subjectAltName | grep -Fq 'IP Address:10.254.240.2' || fail 'regional SAN is incorrect'
[[ "$(stat -c '%a' "${output_dir}")" == 700 ]] || fail 'PKI directory is not mode 0700'
find "${output_dir}" -type f -name '*.key' ! -perm 0600 -print -quit | grep -q . && fail 'a private key is not mode 0600'
find "${output_dir}" -type f -name '*.crt' ! -perm 0644 -print -quit | grep -q . && fail 'a certificate is not mode 0644'
find "${output_dir}" -type f \( -name '*.csr' -o -name '*.extensions.*' \) -print -quit | grep -q . && fail 'temporary issuance material remains'

weak_file="${test_root}/weak"
printf '%s\n' 'too-short' > "${weak_file}"
chmod 0600 "${weak_file}"
if bash "${ROOT}/deploy/host/generate-management-pki.sh" "${test_root}/weak-output" \
  --passphrase-file "${weak_file}" >/dev/null 2>&1; then
  fail 'generator accepted a weak CA passphrase'
fi
[[ ! -e "${test_root}/weak-output" ]] || fail 'weak passphrase created partial PKI state'

printf 'Management PKI tests passed.\n'
