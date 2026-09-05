#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-cicd-test.XXXXXX")"
cleanup() { rm -rf -- "${tmp}"; }
trap cleanup EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

bash "${ROOT_DIR}/scripts/release/validate-deployment-environment-map.sh" >/dev/null
digest_a="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
digest_b="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
cat > "${tmp}/variables.env" <<'EOF'
DEPLOYMENT_PROFILE=principal
DOMAIN=vpn.example.test
POSTGRES_ADMIN_USER=admin
EOF
cat > "${tmp}/secrets.env" <<'EOF'
POSTGRES_ADMIN_PASSWORD=a-secret-value
CONTROL_DATA_ENCRYPTION_KEY=another-secret-value
EOF
chmod 0600 "${tmp}/variables.env" "${tmp}/secrets.env"
bash "${ROOT_DIR}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/variables.env" --secrets-file "${tmp}/secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core@${digest_a}" \
  --control-image "ghcr.io/goastian/midori-vpn-control@${digest_b}" \
  --output "${tmp}/deployment.env" >/dev/null
grep -Fqx "CORE_IMAGE=ghcr.io/goastian/midori-vpn-core@${digest_a}" "${tmp}/deployment.env" || fail "Core digest was not injected"
grep -Fqx 'POSTGRES_ADMIN_PASSWORD=a-secret-value' "${tmp}/deployment.env" || fail "secret fragment was not composed"
[[ "$(stat -c '%a' "${tmp}/deployment.env")" == 600 ]] || fail "deployment values are not private"

printf 'POSTGRES_ADMIN_PASSWORD=wrong-channel\n' > "${tmp}/bad-variable.env"
chmod 0600 "${tmp}/bad-variable.env"
if bash "${ROOT_DIR}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/bad-variable.env" --secrets-file "${tmp}/secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core@${digest_a}" \
  --control-image "ghcr.io/goastian/midori-vpn-control@${digest_b}" \
  --output "${tmp}/bad.env" >/dev/null 2>&1; then
  fail "secret-classified value was accepted from Actions variables"
fi
printf 'CORE_IMAGE=ghcr.io/evil/image@%s\n' "${digest_a}" > "${tmp}/image-override.env"
chmod 0600 "${tmp}/image-override.env"
if bash "${ROOT_DIR}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/image-override.env" --secrets-file "${tmp}/secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core@${digest_a}" \
  --control-image "ghcr.io/goastian/midori-vpn-control@${digest_b}" \
  --output "${tmp}/bad-image.env" >/dev/null 2>&1; then
  fail "an Actions fragment replaced a verified image digest"
fi

workspace="${tmp}/workspace"
mkdir -p "${workspace}"
for component in core control desktop extension; do
  case "${component}" in
    core) path="${workspace}" ;;
    control) path="${workspace}/midori-vpn-control" ;;
    desktop) path="${workspace}/midori-vpn-desktop" ;;
    extension) path="${workspace}/midorivpn-extension" ;;
  esac
  mkdir -p "${path}"
  git -C "${path}" init -q
  git -C "${path}" config user.name 'Release Test'
  git -C "${path}" config user.email release-test@example.invalid
  case "${component}" in
    core)
      printf '2.0.0\n' > "${path}/VERSION"
      printf 'midori-vpn-control/\nmidori-vpn-desktop/\nmidorivpn-extension/\n' > "${path}/.gitignore"
      ;;
    control)
      printf '{"version":"2.0.0"}\n' > "${path}/package.json"
      mkdir -p "${path}/.container"
      printf 'FROM scratch\n' > "${path}/.container/Containerfile"
      ;;
    desktop)
      printf '{"version":"2.0.0"}\n' > "${path}/package.json"
      mkdir -p "${path}/packaging" "${path}/agent"
      printf 'Name: midori-vpn\nVersion: 2.0.0\n' > "${path}/packaging/midori-vpn.spec"
      printf 'module example.invalid/agent\n' > "${path}/agent/go.mod"
      ;;
    extension)
      printf '{"version":"2.0.0"}\n' > "${path}/package.json"
      mkdir -p "${path}/manifest"
      printf '{"version":"2.0.0"}\n' > "${path}/manifest/main.json"
      ;;
  esac
  git -C "${path}" add .
  git -C "${path}" commit -qm 'Freeze test source'
  git -C "${path}" tag -a v2.0.0 -m 'MidoriVPN 2.0.0 test tag'
done
MIDORIVPN_WORKSPACE_ROOT="${workspace}" bash "${ROOT_DIR}/scripts/release/verify-coordinated-tags.sh" \
  v2.0.0 "${tmp}/workspace-manifest.json" >/dev/null
jq -e '.schema_version == 2 and (.repositories | length == 4)' "${tmp}/workspace-manifest.json" >/dev/null || fail "coordinated manifest is incomplete"
git -C "${workspace}/midorivpn-extension" tag -d v2.0.0 >/dev/null
git -C "${workspace}/midorivpn-extension" tag v2.0.0
if MIDORIVPN_WORKSPACE_ROOT="${workspace}" bash "${ROOT_DIR}/scripts/release/verify-coordinated-tags.sh" \
  v2.0.0 "${tmp}/bad-manifest.json" >/dev/null 2>&1; then
  fail "a lightweight component tag was accepted"
fi

mkdir -p "${tmp}/one" "${tmp}/two"
bash "${ROOT_DIR}/scripts/release/create-deployment-bundle.sh" \
  --manifest "${tmp}/workspace-manifest.json" --core-digest "${digest_a}" --control-digest "${digest_b}" \
  --output-dir "${tmp}/one/midorivpn-2.0.0" >/dev/null
bash "${ROOT_DIR}/scripts/release/create-deployment-bundle.sh" \
  --manifest "${tmp}/workspace-manifest.json" --core-digest "${digest_a}" --control-digest "${digest_b}" \
  --output-dir "${tmp}/two/midorivpn-2.0.0" >/dev/null
cmp --silent "${tmp}/one/midorivpn-2.0.0.tar.gz" "${tmp}/two/midorivpn-2.0.0.tar.gz" || fail "deployment bundle is not reproducible"
(cd "${tmp}/one" && sha256sum --check midorivpn-2.0.0.tar.gz.sha256 >/dev/null) || fail "bundle checksum is invalid"
if rg -n 'a-secret-value|another-secret-value|-----BEGIN (OPENSSH|PRIVATE) KEY-----' "${tmp}/one/midorivpn-2.0.0" >/dev/null; then
  fail "deployment bundle contains secret material"
fi
jq -e '.images.core | endswith("@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")' \
  "${tmp}/one/midorivpn-2.0.0/release.json" >/dev/null || fail "bundle release metadata lacks Core digest"
bash "${tmp}/one/midorivpn-2.0.0/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/variables.env" --secrets-file "${tmp}/secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core@${digest_a}" \
  --control-image "ghcr.io/goastian/midori-vpn-control@${digest_b}" \
  --output "${tmp}/bundle-deployment.env" >/dev/null || fail "bundle cannot compose deployment values independently"

for workflow in "${ROOT_DIR}/.github/workflows/publish.yml" "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml"; do
  if rg -n 'workflow_dispatch|ubuntu-latest|cosign-release: v3\.1\.2|uses: [^ ]+@(v|main|master)([ #]|$)' "${workflow}" >/dev/null; then
    fail "workflow contains a manual trigger, floating action or obsolete release input: ${workflow}"
  fi
done
printf 'Tagged private CI/CD tests passed.\n'
