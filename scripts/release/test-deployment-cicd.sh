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
release_version="2.0.0-rc.1"
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
  --core-image "ghcr.io/goastian/midori-vpn-core:${release_version}" \
  --control-image "ghcr.io/goastian/midori-vpn-control:${release_version}" \
  --output "${tmp}/deployment.env" >/dev/null
grep -Fqx "CORE_IMAGE=ghcr.io/goastian/midori-vpn-core:${release_version}" "${tmp}/deployment.env" || fail "Core version tag was not injected"
grep -Fqx "CONTROL_IMAGE=ghcr.io/goastian/midori-vpn-control:${release_version}" "${tmp}/deployment.env" || fail "Control version tag was not injected for the principal"
grep -Fqx 'POSTGRES_ADMIN_PASSWORD=a-secret-value' "${tmp}/deployment.env" || fail "secret fragment was not composed"
[[ "$(stat -c '%a' "${tmp}/deployment.env")" == 600 ]] || fail "deployment values are not private"

cat > "${tmp}/regional-variables.env" <<'EOF'
DEPLOYMENT_PROFILE=core-node
DOMAIN=regional.example.test
EOF
cat > "${tmp}/regional-secrets.env" <<'EOF'
REDIS_PASSWORD=regional-secret-value
EOF
chmod 0600 "${tmp}/regional-variables.env" "${tmp}/regional-secrets.env"
bash "${ROOT_DIR}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/regional-variables.env" --secrets-file "${tmp}/regional-secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core:${release_version}" \
  --control-image "ghcr.io/goastian/midori-vpn-control:${release_version}" \
  --output "${tmp}/regional-deployment.env" >/dev/null
grep -Fqx "CORE_IMAGE=ghcr.io/goastian/midori-vpn-core:${release_version}" "${tmp}/regional-deployment.env" || fail "regional Core version tag was not injected"
if grep -q '^CONTROL_IMAGE=' "${tmp}/regional-deployment.env"; then
  fail "regional deployment received the principal-only Control image"
fi

cat > "${tmp}/missing-profile.env" <<'EOF'
DOMAIN=vpn.example.test
EOF
chmod 0600 "${tmp}/missing-profile.env"
if bash "${ROOT_DIR}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/missing-profile.env" --secrets-file "${tmp}/secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core:${release_version}" \
  --control-image "ghcr.io/goastian/midori-vpn-control:${release_version}" \
  --output "${tmp}/missing-profile-output.env" >/dev/null 2>&1; then
  fail "deployment values without an explicit profile were accepted"
fi

printf 'POSTGRES_ADMIN_PASSWORD=wrong-channel\n' > "${tmp}/bad-variable.env"
chmod 0600 "${tmp}/bad-variable.env"
if bash "${ROOT_DIR}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/bad-variable.env" --secrets-file "${tmp}/secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core:${release_version}" \
  --control-image "ghcr.io/goastian/midori-vpn-control:${release_version}" \
  --output "${tmp}/bad.env" >/dev/null 2>&1; then
  fail "secret-classified value was accepted from Actions variables"
fi
printf 'CORE_IMAGE=ghcr.io/evil/image:%s\n' "${release_version}" > "${tmp}/image-override.env"
chmod 0600 "${tmp}/image-override.env"
if bash "${ROOT_DIR}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/image-override.env" --secrets-file "${tmp}/secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core:${release_version}" \
  --control-image "ghcr.io/goastian/midori-vpn-control:${release_version}" \
  --output "${tmp}/bad-image.env" >/dev/null 2>&1; then
  fail "an Actions fragment replaced a verified image tag"
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
  git -C "${path}" tag -a v2.0.0-rc.1 -m 'MidoriVPN 2.0.0-rc.1 test tag'
done
MIDORIVPN_WORKSPACE_ROOT="${workspace}" bash "${ROOT_DIR}/scripts/release/verify-coordinated-tags.sh" \
  v2.0.0-rc.1 "${tmp}/workspace-manifest.json" >/dev/null
jq -e '.schema_version == 3 and .product_version == "2.0.0" and .release_version == "2.0.0-rc.1" and .git_tag == "v2.0.0-rc.1" and ([.repositories[].repository] | all(endswith("-dev"))) and (.repositories | length == 4)' "${tmp}/workspace-manifest.json" >/dev/null || fail "coordinated manifest is incomplete"
git -C "${workspace}/midorivpn-extension" tag -d v2.0.0-rc.1 >/dev/null
git -C "${workspace}/midorivpn-extension" tag v2.0.0-rc.1
if MIDORIVPN_WORKSPACE_ROOT="${workspace}" bash "${ROOT_DIR}/scripts/release/verify-coordinated-tags.sh" \
  v2.0.0-rc.1 "${tmp}/bad-manifest.json" >/dev/null 2>&1; then
  fail "a lightweight component tag was accepted"
fi

mkdir -p "${tmp}/one" "${tmp}/two"
bash "${ROOT_DIR}/scripts/release/create-deployment-bundle.sh" \
  --manifest "${tmp}/workspace-manifest.json" --core-digest "${digest_a}" --control-digest "${digest_b}" \
  --output-dir "${tmp}/one/midorivpn-${release_version}" >/dev/null
bash "${ROOT_DIR}/scripts/release/create-deployment-bundle.sh" \
  --manifest "${tmp}/workspace-manifest.json" --core-digest "${digest_a}" --control-digest "${digest_b}" \
  --output-dir "${tmp}/two/midorivpn-${release_version}" >/dev/null
cmp --silent "${tmp}/one/midorivpn-${release_version}.tar.gz" "${tmp}/two/midorivpn-${release_version}.tar.gz" || fail "deployment bundle is not reproducible"
(cd "${tmp}/one" && sha256sum --check "midorivpn-${release_version}.tar.gz.sha256" >/dev/null) || fail "bundle checksum is invalid"
if rg -n 'a-secret-value|another-secret-value|-----BEGIN (OPENSSH|PRIVATE) KEY-----' "${tmp}/one/midorivpn-${release_version}" >/dev/null; then
  fail "deployment bundle contains secret material"
fi
jq -e '.schema_version == 2 and .product_version == "2.0.0" and .release_version == "2.0.0-rc.1" and .git_tag == "v2.0.0-rc.1" and .images.core.pull_ref == "ghcr.io/goastian/midori-vpn-core:2.0.0-rc.1" and .images.core.digest == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' \
  "${tmp}/one/midorivpn-${release_version}/release.json" >/dev/null || fail "bundle release metadata is incomplete"
[[ -f "${tmp}/one/midorivpn-${release_version}/docs/PRODUCTION_DEPLOYMENT.md" ]] || fail "bundle lacks the production runbook"
[[ -f "${tmp}/one/midorivpn-${release_version}/deploy/DEPLOYMENT_PROFILES.md" ]] || fail "bundle lacks deployment profile documentation"
[[ -f "${tmp}/one/midorivpn-${release_version}/.env.example" ]] || fail "bundle lacks the environment reference"
[[ -f "${tmp}/one/midorivpn-${release_version}/docs/openapi.yaml" ]] || fail "bundle documentation links are incomplete"
[[ -f "${tmp}/one/midorivpn-${release_version}/scripts/release/resolve-runtime-images.sh" ]] || fail "bundle lacks the runtime image resolver"
bash "${tmp}/one/midorivpn-${release_version}/scripts/release/compose-deployment-values.sh" \
  --variables-file "${tmp}/variables.env" --secrets-file "${tmp}/secrets.env" \
  --core-image "ghcr.io/goastian/midori-vpn-core:${release_version}" \
  --control-image "ghcr.io/goastian/midori-vpn-control:${release_version}" \
  --output "${tmp}/bundle-deployment.env" >/dev/null || fail "bundle cannot compose deployment values independently"

cat > "${tmp}/runtime.env" <<EOF
DEPLOYMENT_PROFILE=core-node
CORE_IMAGE=ghcr.io/goastian/midori-vpn-core:${release_version}
POD_INFRA_IMAGE=registry.k8s.io/pause:3.10.1
REDIS_IMAGE=docker.io/library/redis:8.2.1-alpine
OPENVPN_ENABLED=false
IKEV2_ENABLED=false
EOF
chmod 0600 "${tmp}/runtime.env"
fake_bin="${tmp}/fake-bin"
mkdir -p "${fake_bin}"
cat > "${fake_bin}/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
  pull)
    exit 0
    ;;
  image)
    [[ "${2:-}" == inspect && "${3:-}" == --format ]]
    format="${4:-}"
    ref="${5:-}"
    case "${format}" in
      *RepoDigests*)
        repository="${ref%:*}"
        digest="${FAKE_OTHER_DIGEST}"
        [[ "${ref}" != ghcr.io/goastian/midori-vpn-core:* ]] || digest="${FAKE_CORE_DIGEST}"
        printf '%s@%s\n' "${repository}" "${digest}"
        ;;
      *revision*) printf '%s\n' "${FAKE_CORE_COMMIT}" ;;
      *version*) printf '%s\n' "${FAKE_RELEASE_VERSION}" ;;
      *) exit 2 ;;
    esac
    ;;
  *) exit 2 ;;
esac
EOF
chmod 0700 "${fake_bin}/docker"
core_commit="$(jq -r '.repositories[] | select(.component == "core") | .commit' "${tmp}/workspace-manifest.json")"
PATH="${fake_bin}:${PATH}" FAKE_CORE_DIGEST="${digest_a}" FAKE_OTHER_DIGEST="${digest_b}" \
  FAKE_CORE_COMMIT="${core_commit}" FAKE_RELEASE_VERSION="${release_version}" \
  CONTAINER_ENGINE=docker bash "${tmp}/one/midorivpn-${release_version}/scripts/release/resolve-runtime-images.sh" \
    --env-file "${tmp}/runtime.env" \
    --release-json "${tmp}/one/midorivpn-${release_version}/release.json" \
    --workspace-manifest "${tmp}/workspace-manifest.json" \
    --output "${tmp}/runtime-images.json" >/dev/null
jq -e '.schema_version == 1 and .release_version == "2.0.0-rc.1" and (.images | length == 3) and (.images[] | select(.key == "CORE_IMAGE") | .digest == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")' \
  "${tmp}/runtime-images.json" >/dev/null || fail "runtime image lock is incomplete"
if PATH="${fake_bin}:${PATH}" FAKE_CORE_DIGEST="${digest_b}" FAKE_OTHER_DIGEST="${digest_b}" \
  FAKE_CORE_COMMIT="${core_commit}" FAKE_RELEASE_VERSION="${release_version}" \
  CONTAINER_ENGINE=docker bash "${tmp}/one/midorivpn-${release_version}/scripts/release/resolve-runtime-images.sh" \
    --env-file "${tmp}/runtime.env" \
    --release-json "${tmp}/one/midorivpn-${release_version}/release.json" \
    --workspace-manifest "${tmp}/workspace-manifest.json" \
    --output "${tmp}/bad-runtime-images.json" >/dev/null 2>&1; then
  fail "runtime image resolver accepted a substituted Core tag"
fi

for workflow in "${ROOT_DIR}/.github/workflows/publish.yml" "${ROOT_DIR}/.github/workflows/deploy.yml" "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml"; do
  if rg -n 'workflow_dispatch|ubuntu-latest|cosign-release: v3\.1\.2|uses: [^ ]+@(v|main|master)([ #]|$)' "${workflow}" >/dev/null; then
    fail "workflow contains a manual trigger, floating action or obsolete release input: ${workflow}"
  fi
done
for private_candidate_workflow in "${ROOT_DIR}/.github/workflows/publish.yml" "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml"; do
  if rg -n 'release-production|^[[:space:]]*environment:' "${private_candidate_workflow}" >/dev/null; then
    fail "private candidate workflow depends on an unavailable protected Environment: ${private_candidate_workflow}"
  fi
  [[ "$(rg -Fc 'BUILDX_NO_DEFAULT_ATTESTATIONS: 1' "${private_candidate_workflow}")" == 1 ]] || fail "candidate workflow does not disable default BuildKit attestations: ${private_candidate_workflow}"
  [[ "$(rg -Fc 'provenance: false' "${private_candidate_workflow}")" == 3 ]] || fail "candidate workflow does not disable embedded provenance on all three builds: ${private_candidate_workflow}"
  [[ "$(rg -Fc 'sbom: false' "${private_candidate_workflow}")" == 3 ]] || fail "candidate workflow does not disable embedded SBOM on all three builds: ${private_candidate_workflow}"
  [[ "$(rg -Fc 'cosign attest --yes' "${private_candidate_workflow}")" == 2 ]] || fail "candidate workflow lost independent Cosign provenance or SBOM attestation: ${private_candidate_workflow}"
  [[ "$(rg -Fc 'cosign verify-attestation' "${private_candidate_workflow}")" -ge 2 ]] || fail "candidate workflow does not immediately verify both Cosign attestations: ${private_candidate_workflow}"
  [[ "$(rg -Fc -- '--type slsaprovenance1' "${private_candidate_workflow}")" -ge 2 ]] || fail "candidate workflow does not type SLSA v1 attestation and verification explicitly: ${private_candidate_workflow}"
  [[ "$(rg -Fc -- '--type spdxjson' "${private_candidate_workflow}")" -ge 2 ]] || fail "candidate workflow does not type SPDX attestation and verification explicitly: ${private_candidate_workflow}"
  if rg -n 'uses: actions/attest@|gh attestation verify|artifact-metadata:|attestations:' "${private_candidate_workflow}" >/dev/null; then
    fail "private candidate workflow depends on GitHub artifact attestations unavailable on the organization plan: ${private_candidate_workflow}"
  fi
  [[ "$(rg -Fc -- '-e DOCKER_CONFIG=/auth' "${private_candidate_workflow}")" == 1 ]] || fail "candidate Syft scan does not declare its private registry credential directory: ${private_candidate_workflow}"
  [[ "$(rg -Fc '${HOME}/.docker/config.json:/auth/config.json:ro' "${private_candidate_workflow}")" == 1 ]] || fail "candidate Syft scan does not mount private registry credentials at the declared path: ${private_candidate_workflow}"
  if rg -n 'provenance: mode=max|sbom: true' "${private_candidate_workflow}" >/dev/null; then
    fail "candidate workflow still mixes embedded attestations into its reproducible digest: ${private_candidate_workflow}"
  fi
done
for build_evidence_workflow in "${ROOT_DIR}/.github/workflows/release.yml" "${ROOT_DIR}/midori-vpn-control/.github/workflows/release.yml"; do
  [[ "$(rg -Fc 'BUILDX_NO_DEFAULT_ATTESTATIONS: 1' "${build_evidence_workflow}")" == 1 ]] || fail "build-evidence workflow does not disable default BuildKit attestations: ${build_evidence_workflow}"
  [[ "$(rg -Fc 'provenance: false' "${build_evidence_workflow}")" == 2 ]] || fail "build-evidence workflow does not disable embedded provenance on both builds: ${build_evidence_workflow}"
  [[ "$(rg -Fc 'sbom: false' "${build_evidence_workflow}")" == 2 ]] || fail "build-evidence workflow does not disable embedded SBOM on both builds: ${build_evidence_workflow}"
  if rg -n 'embedded provenance|provenance: mode=max|sbom: true' "${build_evidence_workflow}" >/dev/null; then
    fail "build-evidence workflow retains the non-reproducible attestation contract: ${build_evidence_workflow}"
  fi
done
rg -Fq 'name: Publish - coordinated private OCI candidate' "${ROOT_DIR}/.github/workflows/publish.yml" || fail "Core workflow is not identified as private candidate publication"
rg -Fq 'name: Publish - tagged private Control OCI candidate' "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml" || fail "Control workflow is not identified as private candidate publication"
[[ "$(rg -Fc 'vars.MIDORIVPN_PRIVATE_CANDIDATE_ENABLED' "${ROOT_DIR}/.github/workflows/publish.yml")" == 1 ]] || fail "Core candidate switch is missing or duplicated"
[[ "$(rg -Fc 'vars.MIDORIVPN_PRIVATE_CANDIDATE_ENABLED' "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml")" == 1 ]] || fail "Control candidate switch is missing or duplicated"
core_switch_line="$(rg -n -m1 'vars.MIDORIVPN_PRIVATE_CANDIDATE_ENABLED' "${ROOT_DIR}/.github/workflows/publish.yml" | cut -d: -f1)"
core_private_checkout_line="$(rg -n -m1 'secrets.MIDORIVPN_RELEASE_SOURCE_TOKEN' "${ROOT_DIR}/.github/workflows/publish.yml" | cut -d: -f1)"
((core_switch_line < core_private_checkout_line)) || fail "Core reads a private token before validating the candidate switch"
rg -Fq 'gh api /orgs/goastian/packages/container/midori-vpn-core --jq .visibility' "${ROOT_DIR}/.github/workflows/publish.yml" || fail "Core candidate workflow does not verify private package visibility"
rg -Fq 'gh api /orgs/goastian/packages/container/midori-vpn-control --jq .visibility' "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml" || fail "Control candidate workflow does not verify private package visibility"
if rg -n 'gh api --method PATCH .*/packages/' "${ROOT_DIR}/.github/workflows/publish.yml" "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml" >/dev/null; then
  fail "candidate workflow attempts an unsupported package visibility PATCH"
fi
[[ "$(rg -Fc 'outputs: type=registry,rewrite-timestamp=true' "${ROOT_DIR}/.github/workflows/publish.yml")" == 1 ]] || fail "Core published exporter does not apply the reproducible timestamp contract exactly once"
[[ "$(rg -Fc 'outputs: type=registry,rewrite-timestamp=true' "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml")" == 1 ]] || fail "Control published exporter does not apply the reproducible timestamp contract exactly once"
[[ "$(rg -Fc 'rewrite-timestamp=true' "${ROOT_DIR}/.github/workflows/publish.yml")" == 3 ]] || fail "Core candidate does not normalize all three image exporters"
[[ "$(rg -Fc 'rewrite-timestamp=true' "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml")" == 3 ]] || fail "Control candidate does not normalize all three image exporters"
if rg -Fq 'push: true' "${ROOT_DIR}/.github/workflows/publish.yml" "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml"; then
  fail "candidate workflow bypasses the explicit normalized registry exporter with the push shorthand"
fi
rg -Fq 'name: deploy-production' "${ROOT_DIR}/.github/workflows/deploy.yml" || fail "public production deployment lacks its Environment gate"
rg -Fq "github.repository == 'goastian/midori-vpn-core-dev'" "${ROOT_DIR}/.github/workflows/publish.yml" || fail "private Core publisher lacks a repository guard"
rg -Fq "github.repository == 'goastian/midori-vpn-control-dev'" "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml" || fail "private Control publisher lacks a repository guard"
rg -Fq "github.repository == 'goastian/midori-vpn-core'" "${ROOT_DIR}/.github/workflows/deploy.yml" || fail "public deploy controller lacks a repository guard"
[[ "$(rg -Fc 'token: ${{ secrets.MIDORIVPN_RELEASE_SOURCE_TOKEN }}' "${ROOT_DIR}/.github/workflows/publish.yml")" == 3 ]] || fail "private source checkouts do not use the dedicated source token"
if rg -Fq 'token: ${{ secrets.MIDORIVPN_RELEASE_READ_TOKEN }}' "${ROOT_DIR}/.github/workflows/publish.yml"; then
  fail "the package token is still used for private source checkout"
fi
[[ "$(rg -Fc 'password: ${{ secrets.MIDORIVPN_RELEASE_READ_TOKEN }}' "${ROOT_DIR}/.github/workflows/publish.yml")" == 1 ]] || fail "private Control pull does not use the dedicated package read token"
[[ "$(rg -Fc 'username: ${{ vars.MIDORIVPN_RELEASE_READ_USER }}' "${ROOT_DIR}/.github/workflows/publish.yml")" == 1 ]] || fail "private Control pull does not use the dedicated read identity"
[[ "$(rg -Fc 'password: ${{ secrets.GITHUB_TOKEN }}' "${ROOT_DIR}/.github/workflows/publish.yml")" == 1 ]] || fail "Core publication does not restore its job-scoped registry credential"
[[ "$(rg -Fc 'cosign verify-attestation' "${ROOT_DIR}/.github/workflows/publish.yml")" == 4 ]] || fail "Core candidate does not verify both Control and Core OCI attestations"
[[ "$(rg -Fc 'cosign verify-attestation' "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml")" == 2 ]] || fail "Control candidate does not verify both OCI attestations"
[[ "$(rg -Fc 'cosign verify-attestation' "${ROOT_DIR}/scripts/release/verify-oci-release.sh")" == 2 ]] || fail "host verifier does not verify both OCI attestations"
[[ "$(rg -Fc -- '--type slsaprovenance1' "${ROOT_DIR}/scripts/release/verify-oci-release.sh")" == 1 ]] || fail "host verifier does not require the SLSA v1 predicate type"
[[ "$(rg -Fc -- '--type spdxjson' "${ROOT_DIR}/scripts/release/verify-oci-release.sh")" == 1 ]] || fail "host verifier does not require the SPDX JSON predicate type"
if rg -n 'gh attestation verify' "${ROOT_DIR}/.github/workflows/publish.yml" "${ROOT_DIR}/midori-vpn-control/.github/workflows/publish.yml" "${ROOT_DIR}/scripts/release/verify-oci-release.sh" >/dev/null; then
  fail "release verification still depends on GitHub artifact attestation storage"
fi
rg -Fq 'resolve-runtime-images.sh' "${ROOT_DIR}/.github/workflows/deploy.yml" || fail "deploy controller does not lock pulled tags"
rg -Fq -- '--image-lock' "${ROOT_DIR}/.github/workflows/deploy.yml" || fail "deploy controller does not transfer the runtime lock"
rg -Fq 'DEPLOY_SERVICE_USER: ${{ vars.MIDORIVPN_DEPLOY_SERVICE_USER }}' "${ROOT_DIR}/.github/workflows/deploy.yml" || fail "deploy controller does not expose the rootless service user"
[[ "$(rg -Fc -- "--service-user '\$DEPLOY_SERVICE_USER'" "${ROOT_DIR}/.github/workflows/deploy.yml")" == 2 ]] || fail "deploy controller does not consistently use the validated service user"
if rg -Fq -- '--service-user midorivpn' "${ROOT_DIR}/.github/workflows/deploy.yml"; then
  fail "deploy controller still hard-codes the rootless service user"
fi
printf 'Tagged private CI/CD tests passed.\n'
