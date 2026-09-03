#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_RUNNER="${SOURCE_DIR}/pod.sh"
SOURCE_LAYOUT="${SOURCE_DIR}/lib/workspace-layout.sh"
TEST_DIR="$(mktemp -d /tmp/midorivpn-pod-runner.XXXXXX)"
trap 'rm -rf "${TEST_DIR}"' EXIT

fail() {
    echo "error: $*" >&2
    exit 1
}

make_fake_podman() {
    local bin_dir="$1"
    mkdir -p "${bin_dir}"
    cat >"${bin_dir}/podman" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${PODMAN_LOG:?}"
exit 0
EOF
    chmod +x "${bin_dir}/podman"
}

make_repo_set() {
    local base="$1"
    local layout="$2"
    local core="${base}/midori-vpn-core"
    mkdir -p "${core}/scripts/lib" "${core}/.container" "${core}/cmd" "${core}/internal/db/migrations"
    cp "${SOURCE_RUNNER}" "${core}/scripts/pod.sh"
    cp "${SOURCE_LAYOUT}" "${core}/scripts/lib/workspace-layout.sh"
    : >"${core}/.container/Containerfile"

    if [[ "${layout}" == "nested" ]]; then
        mkdir -p \
            "${core}/midori-vpn-control/.container" "${core}/midori-vpn-control/src" \
            "${core}/midori-vpn-desktop/agent" \
            "${core}/midorivpn-extension/src" "${core}/midorivpn-extension/manifest"
        : >"${core}/midori-vpn-control/.container/Containerfile"
        : >"${core}/midori-vpn-control/package.json"
        : >"${core}/midori-vpn-desktop/package.json"
        : >"${core}/midori-vpn-desktop/agent/go.mod"
        : >"${core}/midorivpn-extension/package.json"
        : >"${core}/midorivpn-extension/manifest/main.json"
    else
        mkdir -p \
            "${base}/midori-vpn-control/.container" "${base}/midori-vpn-control/src" \
            "${base}/midori-vpn-desktop/agent" \
            "${base}/midorivpn-extension/src" "${base}/midorivpn-extension/manifest"
        : >"${base}/midori-vpn-control/.container/Containerfile"
        : >"${base}/midori-vpn-control/package.json"
        : >"${base}/midori-vpn-desktop/package.json"
        : >"${base}/midori-vpn-desktop/agent/go.mod"
        : >"${base}/midorivpn-extension/package.json"
        : >"${base}/midorivpn-extension/manifest/main.json"
    fi
}

FAKE_BIN="${TEST_DIR}/bin"
PODMAN_LOG="${TEST_DIR}/podman.log"
export PODMAN_LOG
make_fake_podman "${FAKE_BIN}"

NESTED="${TEST_DIR}/nested"
make_repo_set "${NESTED}" nested
: >"${PODMAN_LOG}"
(
    cd "${NESTED}/midori-vpn-core/midori-vpn-control"
    PATH="${FAKE_BIN}:${PATH}" bash ../scripts/pod.sh npm --version
)
rg -F -- "-v ${NESTED}/midori-vpn-core:/workspace:z" "${PODMAN_LOG}" >/dev/null || fail "nested Core mount changed"
rg -F -- "-w /workspace/midori-vpn-control" "${PODMAN_LOG}" >/dev/null || fail "nested workdir changed"
rg -F -- "-v midori_npm_modules_midori-vpn-control:/workspace/midori-vpn-control/node_modules:z" "${PODMAN_LOG}" >/dev/null || fail "nested npm cache changed"

SIBLING="${TEST_DIR}/sibling"
make_repo_set "${SIBLING}" sibling
: >"${PODMAN_LOG}"
(
    cd "${SIBLING}/midori-vpn-desktop/agent"
    PATH="${FAKE_BIN}:${PATH}" bash ../../midori-vpn-core/scripts/pod.sh go env GOMOD
)
rg -F -- "-v ${SIBLING}/midori-vpn-desktop:/external/midori-vpn-desktop:z" "${PODMAN_LOG}" >/dev/null || fail "sibling Desktop was not mounted"
rg -F -- "-v ${SIBLING}/midori-vpn-control:/external/midori-vpn-control:z" "${PODMAN_LOG}" >/dev/null || fail "sibling Control was not mounted"
rg -F -- "-w /external/midori-vpn-desktop/agent" "${PODMAN_LOG}" >/dev/null || fail "sibling workdir is incorrect"

: >"${PODMAN_LOG}"
(
    cd "${SIBLING}/midori-vpn-core"
    PATH="${FAKE_BIN}:${PATH}" bash scripts/pod.sh audit >/dev/null
    PATH="${FAKE_BIN}:${PATH}" bash scripts/pod.sh debt >/dev/null
)
rg -F -- "-w /external/midori-vpn-desktop/agent" "${PODMAN_LOG}" >/dev/null || fail "sibling agent audit workdir is incorrect"
rg -F -- "-w /external/midori-vpn-control" "${PODMAN_LOG}" >/dev/null || fail "sibling Control audit workdir is incorrect"
rg -F -- "-w /external/midorivpn-extension" "${PODMAN_LOG}" >/dev/null || fail "sibling extension audit workdir is incorrect"

: >"${PODMAN_LOG}"
if (
    cd "${SIBLING}/midori-vpn-core"
    PATH="${FAKE_BIN}:${PATH}" bash scripts/pod.sh go list ./...
) >"${TEST_DIR}/broad-go.out" 2>"${TEST_DIR}/broad-go.err"; then
    fail "Core root accepted an ambiguous ./... Go scope"
fi
rg -F 'ambiguous ./... from the Core root includes nested repositories and tmp/staging' \
    "${TEST_DIR}/broad-go.err" >/dev/null || fail "ambiguous Go scope error is not actionable"
[[ ! -s "${PODMAN_LOG}" ]] || fail "Podman ran for an ambiguous Core Go scope"

(
    cd "${SIBLING}/midori-vpn-core"
    PATH="${FAKE_BIN}:${PATH}" bash scripts/pod.sh go test ./cmd/... ./internal/...
)
rg -F -- 'go test ./cmd/... ./internal/...' "${PODMAN_LOG}" >/dev/null || fail "explicit Core Go scopes were not forwarded"

: >"${PODMAN_LOG}"
(
    cd "${SIBLING}/midori-vpn-desktop/agent"
    PATH="${FAKE_BIN}:${PATH}" bash ../../midori-vpn-core/scripts/pod.sh go test ./...
)
rg -F -- 'go test ./...' "${PODMAN_LOG}" >/dev/null || fail "isolated agent module rejected ./..."

: >"${PODMAN_LOG}"
if (
    cd "${SIBLING}/midori-vpn-core"
    PATH="${FAKE_BIN}:${PATH}" bash scripts/pod.sh staticcheck ./...
) >"${TEST_DIR}/broad-staticcheck.out" 2>"${TEST_DIR}/broad-staticcheck.err"; then
    fail "Core root staticcheck accepted an ambiguous ./... scope"
fi
rg -F 'ambiguous ./... from the Core root includes nested repositories and tmp/staging' \
    "${TEST_DIR}/broad-staticcheck.err" >/dev/null || fail "ambiguous staticcheck error is not actionable"
[[ ! -s "${PODMAN_LOG}" ]] || fail "Podman ran for an ambiguous Core staticcheck scope"

(
    cd "${SIBLING}/midori-vpn-core"
    PATH="${FAKE_BIN}:${PATH}" bash scripts/pod.sh shellcheck scripts/pod.sh
)
rg -F -- '-w /workspace' "${PODMAN_LOG}" >/dev/null || fail "ShellCheck root workdir is incorrect"
rg -F -- 'shellcheck-alpine@sha256:c82fe42504fbc9fc68f15d36638e5ee2324ebb8b94e96a3c4e395bf361c49183 shellcheck scripts/pod.sh' \
    "${PODMAN_LOG}" >/dev/null || fail "pinned ShellCheck command was not forwarded"

retired_core_token='VPN_CORE''_TOKEN'
printf 'package retired\nconst name = "%s"\n' "${retired_core_token}" >"${SIBLING}/midori-vpn-core/internal/retired.go"
if (
    cd "${SIBLING}/midori-vpn-core"
    PATH="${FAKE_BIN}:${PATH}" bash scripts/pod.sh debt
) >"${TEST_DIR}/retired.out" 2>"${TEST_DIR}/retired.err"; then
    fail "debt gate accepted a retired authentication contract"
fi
rg -F "se encontró el contrato retirado ${retired_core_token} en código vivo" "${TEST_DIR}/retired.err" >/dev/null || \
    fail "retired-contract error is not actionable"
rm -f "${SIBLING}/midori-vpn-core/internal/retired.go"

mkdir -p "${TEST_DIR}/unrelated"
: >"${PODMAN_LOG}"
if (
    cd "${TEST_DIR}/unrelated"
    PATH="${FAKE_BIN}:${PATH}" bash "${SIBLING}/midori-vpn-core/scripts/pod.sh" go env GOMOD
) >"${TEST_DIR}/unrelated.out" 2>"${TEST_DIR}/unrelated.err"; then
    fail "unrelated directory was accepted"
fi
rg -F 'current directory is not inside a resolved MidoriVPN repository' "${TEST_DIR}/unrelated.err" >/dev/null || fail "unrelated-directory error is not actionable"
[[ ! -s "${PODMAN_LOG}" ]] || fail "Podman ran for an unrelated directory"

echo "Podman runner layout tests passed."
