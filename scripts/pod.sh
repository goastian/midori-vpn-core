#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# Midori VPN — Podman Rootless Unified Runner
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CURRENT_DIR="$(pwd -P)"
# shellcheck source=scripts/lib/workspace-layout.sh
source "${SCRIPT_DIR}/lib/workspace-layout.sh"

die() {
    echo "error: $*" >&2
    exit 1
}

CONTROL_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midori-vpn-control || true)"
DESKTOP_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midori-vpn-desktop || true)"
EXTENSION_DIR="$(midorivpn_resolve_related_repo "${ROOT_DIR}" midorivpn-extension || true)"

CONTROL_CONTAINER_DIR=""
DESKTOP_CONTAINER_DIR=""
EXTENSION_CONTAINER_DIR=""
[[ -z "${CONTROL_DIR}" ]] || CONTROL_CONTAINER_DIR="$(midorivpn_container_repo_root "${ROOT_DIR}" "${CONTROL_DIR}" midori-vpn-control)"
[[ -z "${DESKTOP_DIR}" ]] || DESKTOP_CONTAINER_DIR="$(midorivpn_container_repo_root "${ROOT_DIR}" "${DESKTOP_DIR}" midori-vpn-desktop)"
[[ -z "${EXTENSION_DIR}" ]] || EXTENSION_CONTAINER_DIR="$(midorivpn_container_repo_root "${ROOT_DIR}" "${EXTENSION_DIR}" midorivpn-extension)"

CURRENT_REPO_DIR=""
CURRENT_CONTAINER_DIR=""
for repo_spec in \
    "${CONTROL_DIR}|${CONTROL_CONTAINER_DIR}" \
    "${DESKTOP_DIR}|${DESKTOP_CONTAINER_DIR}" \
    "${EXTENSION_DIR}|${EXTENSION_CONTAINER_DIR}" \
    "${ROOT_DIR}|/workspace"; do
    repo_dir="${repo_spec%%|*}"
    container_dir="${repo_spec#*|}"
    if [[ -n "${repo_dir}" ]] && midorivpn_path_is_within "${CURRENT_DIR}" "${repo_dir}"; then
        CURRENT_REPO_DIR="${repo_dir}"
        CURRENT_CONTAINER_DIR="${container_dir}"
        break
    fi
done

[[ -n "${CURRENT_REPO_DIR}" ]] || die "current directory is not inside a resolved MidoriVPN repository: ${CURRENT_DIR}"

REL_PATH="${CURRENT_DIR#"${CURRENT_REPO_DIR}"}"
REL_PATH="${REL_PATH#/}"
WORKDIR_IN_CONTAINER="${CURRENT_CONTAINER_DIR}${REL_PATH:+/${REL_PATH}}"
if midorivpn_path_is_within "${WORKDIR_IN_CONTAINER}" "/workspace"; then
    CACHE_KEY="${WORKDIR_IN_CONTAINER#/workspace}"
    CACHE_KEY="${CACHE_KEY#/}"
else
    CACHE_KEY="${WORKDIR_IN_CONTAINER#/}"
fi
CACHE_KEY="${CACHE_KEY//\//_}"
NODE_MODULES_VOLUME="midori_npm_modules_${CACHE_KEY:-root}"

PODMAN_WORKSPACE_MOUNTS=(-v "${ROOT_DIR}:/workspace:z")
for repo_spec in \
    "${CONTROL_DIR}|${CONTROL_CONTAINER_DIR}" \
    "${DESKTOP_DIR}|${DESKTOP_CONTAINER_DIR}" \
    "${EXTENSION_DIR}|${EXTENSION_CONTAINER_DIR}"; do
    repo_dir="${repo_spec%%|*}"
    container_dir="${repo_spec#*|}"
    if [[ -n "${repo_dir}" ]] && ! midorivpn_path_is_within "${repo_dir}" "${ROOT_DIR}"; then
        PODMAN_WORKSPACE_MOUNTS+=(-v "${repo_dir}:${container_dir}:z")
    fi
done

# Image Names
IMAGE_GO="localhost/midori-dev-go:latest"
IMAGE_NODE="localhost/midori-dev-node:latest"
IMAGE_PROMETHEUS="docker.io/prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
IMAGE_SYFT="ghcr.io/anchore/syft@sha256:41f8289664101d6ebab30a97ac8df6b6f86b92d8343285ca90f428e2bc353106"
IMAGE_SHELLCHECK="docker.io/koalaman/shellcheck-alpine@sha256:c82fe42504fbc9fc68f15d36638e5ee2324ebb8b94e96a3c4e395bf361c49183"
PODMAN_USERNS=("--userns=keep-id:uid=0,gid=0")
PODMAN_GO_ENV=()
if [[ -n "${TEST_DATABASE_URL:-}" ]]; then
    PODMAN_GO_ENV+=(-e TEST_DATABASE_URL)
fi
PODMAN_GO_NETWORK=()
if [[ -n "${TEST_PODMAN_NETWORK:-}" ]]; then
    [[ -n "${TEST_DATABASE_URL:-}" ]] || die "TEST_PODMAN_NETWORK requires TEST_DATABASE_URL"
    [[ "${TEST_PODMAN_NETWORK}" =~ ^[a-zA-Z0-9_.-]+$ ]] || die "TEST_PODMAN_NETWORK contains invalid characters"
    PODMAN_GO_NETWORK+=(--network "${TEST_PODMAN_NETWORK}")
fi

require_repo() {
    local path="$1"
    local label="$2"
    [[ -n "${path}" ]] || die "${label} repository was not found nested under Core or beside it"
}

reject_ambiguous_core_scope() {
    local argument

    [[ "${CURRENT_DIR}" == "${ROOT_DIR}" ]] || return 0
    for argument in "$@"; do
        if [[ "${argument}" == "./..." ]]; then
            die "ambiguous ./... from the Core root includes nested repositories and tmp/staging; use ./cmd/... ./internal/..."
        fi
    done
}

build_image_if_missing() {
    local img="$1"
    local cfile="$2"
    local context_dir="$3"
    if ! podman image exists "${img}" 2>/dev/null; then
        echo "⚙️ [Podman] Compilando imagen ${img} desde ${cfile}..."
        podman build -t "${img}" -f "${cfile}" "${context_dir}"
    fi
}

cmd_build_images() {
    require_repo "${CONTROL_DIR}" "Control"
    echo "🔨 Construyendo todas las imágenes de desarrollo Podman Rootless..."
    podman build -t "${IMAGE_GO}" -f "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman build -t "${IMAGE_NODE}" -f "${CONTROL_DIR}/.container/Containerfile" "${CONTROL_DIR}"
    echo "✅ Todas las imágenes construidas exitosamente."
}

cmd_go() {
    reject_ambiguous_core_scope "$@"
    build_image_if_missing "${IMAGE_GO}" "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman run --rm "${PODMAN_USERNS[@]}" \
        "${PODMAN_GO_NETWORK[@]}" \
        "${PODMAN_WORKSPACE_MOUNTS[@]}" \
        -v midori_go_pkg:/go/pkg:z \
        -v midori_go_cache:/tmp/go-cache:z \
        -e GOCACHE=/tmp/go-cache \
        "${PODMAN_GO_ENV[@]}" \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_GO}" go "$@"
}

cmd_go_tool() {
    local tool="$1"
    shift
    reject_ambiguous_core_scope "$@"
    build_image_if_missing "${IMAGE_GO}" "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman run --rm "${PODMAN_USERNS[@]}" \
        "${PODMAN_GO_NETWORK[@]}" \
        "${PODMAN_WORKSPACE_MOUNTS[@]}" \
        -v midori_go_pkg:/go/pkg:z \
        -v midori_go_cache:/tmp/go-cache:z \
        -e GOCACHE=/tmp/go-cache \
        "${PODMAN_GO_ENV[@]}" \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_GO}" "${tool}" "$@"
}

cmd_node() {
    require_repo "${CONTROL_DIR}" "Control"
    build_image_if_missing "${IMAGE_NODE}" "${CONTROL_DIR}/.container/Containerfile" "${CONTROL_DIR}"
    podman run --rm "${PODMAN_USERNS[@]}" \
        "${PODMAN_WORKSPACE_MOUNTS[@]}" \
        -v midori_npm_cache:/tmp/npm-cache:z \
        -v "${NODE_MODULES_VOLUME}:${WORKDIR_IN_CONTAINER}/node_modules:z" \
        -e npm_config_cache=/tmp/npm-cache \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_NODE}" "$@"
}

cmd_npm() {
    cmd_node npm "$@"
}

cmd_npx() {
    cmd_node npx "$@"
}

cmd_promtool() {
    podman run --rm "${PODMAN_USERNS[@]}" \
        "${PODMAN_WORKSPACE_MOUNTS[@]}" \
        -w "${WORKDIR_IN_CONTAINER}" \
        --entrypoint /bin/promtool \
        "${IMAGE_PROMETHEUS}" "$@"
}

cmd_syft() {
    podman run --rm "${PODMAN_USERNS[@]}" \
        "${PODMAN_WORKSPACE_MOUNTS[@]}" \
        -e SYFT_CACHE_DIR=/tmp/syft-cache \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_SYFT}" "$@"
}

cmd_shellcheck() {
    podman run --rm "${PODMAN_USERNS[@]}" \
        "${PODMAN_WORKSPACE_MOUNTS[@]}" \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_SHELLCHECK}" shellcheck -x "$@"
}

cmd_audit() {
    require_repo "${CONTROL_DIR}" "Control"
    require_repo "${DESKTOP_DIR}" "Desktop"
    require_repo "${EXTENSION_DIR}" "Extension"
    echo "🛡️ [1/2] Ejecutando govulncheck en Core y Agente..."
    build_image_if_missing "${IMAGE_GO}" "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman run --rm "${PODMAN_USERNS[@]}" \
        "${PODMAN_WORKSPACE_MOUNTS[@]}" \
        -w "/workspace" \
        "${IMAGE_GO}" govulncheck ./cmd/... ./internal/...

    podman run --rm "${PODMAN_USERNS[@]}" \
        "${PODMAN_WORKSPACE_MOUNTS[@]}" \
        -w "${DESKTOP_CONTAINER_DIR}/agent" \
        "${IMAGE_GO}" govulncheck ./...

    echo "🛡️ [2/2] Ejecutando npm audit en Frontends..."
    build_image_if_missing "${IMAGE_NODE}" "${CONTROL_DIR}/.container/Containerfile" "${CONTROL_DIR}"
    for repo_spec in \
        "midori-vpn-control|${CONTROL_CONTAINER_DIR}" \
        "midorivpn-extension|${EXTENSION_CONTAINER_DIR}" \
        "midori-vpn-desktop|${DESKTOP_CONTAINER_DIR}"; do
        repo_name="${repo_spec%%|*}"
        container_dir="${repo_spec#*|}"
        echo " → Auditando ${repo_name}..."
        podman run --rm "${PODMAN_USERNS[@]}" \
            "${PODMAN_WORKSPACE_MOUNTS[@]}" \
            -w "${container_dir}" \
            "${IMAGE_NODE}" npm audit --audit-level=high
    done
    
    echo "✅ Auditoría de seguridad completada."
}

cmd_debt() {
    require_repo "${CONTROL_DIR}" "Control"
    require_repo "${DESKTOP_DIR}" "Desktop"
    require_repo "${EXTENSION_DIR}" "Extension"
    local markers='\b(TODO|FIXME|HACK|XXX|DEPRECATED|OBSOLETE|LEGACY)\b'
    local failed=0

    echo "🧹 [1/4] Buscando marcadores obsoletos en código vivo..."
    if rg -n -e "${markers}" \
        --glob '*.{go,ts,tsx,vue,js,mjs,cjs,sh,sql}' \
        --glob '!node_modules/**' --glob '!dist/**' --glob '!.git/**' \
        --glob '!scripts/pod.sh' \
        "${ROOT_DIR}/cmd" "${ROOT_DIR}/internal" \
        "${ROOT_DIR}/scripts" "${CONTROL_DIR}/src" \
        "${DESKTOP_DIR}" "${EXTENSION_DIR}/src"; then
        echo "error: se encontraron marcadores prohibidos de deuda técnica" >&2
        failed=1
    fi

    echo "🧹 [2/4] Verificando pares de migración..."
    local up down base
    for up in "${ROOT_DIR}"/internal/db/migrations/*.up.sql; do
        [ -e "${up}" ] || continue
        base="${up%.up.sql}"
        down="${base}.down.sql"
        if [ ! -f "${down}" ]; then
            echo "error: falta migración reversa ${down}" >&2
            failed=1
        fi
    done
    for down in "${ROOT_DIR}"/internal/db/migrations/*.down.sql; do
        [ -e "${down}" ] || continue
        base="${down%.down.sql}"
        up="${base}.up.sql"
        if [ ! -f "${up}" ]; then
            echo "error: falta migración de avance ${up}" >&2
            failed=1
        fi
    done

    echo "🧹 [3/4] Buscando contratos de autenticación retirados..."
    local retired_core_token='VPN_CORE_TOKEN'
    if rg -n -F "${retired_core_token}" \
        --glob '*.{go,ts,tsx,vue,js,mjs,cjs,sh,sql}' \
        --glob '!node_modules/**' --glob '!dist/**' --glob '!.git/**' \
        --glob '!scripts/pod.sh' \
        "${ROOT_DIR}/cmd" "${ROOT_DIR}/internal" \
        "${ROOT_DIR}/scripts" "${CONTROL_DIR}/src" \
        "${DESKTOP_DIR}" "${EXTENSION_DIR}/src"; then
        echo "error: se encontró el contrato retirado VPN_CORE_TOKEN en código vivo" >&2
        failed=1
    fi

    echo "🧹 [4/4] Confirmando que openpgp no está en el grafo ejecutable..."
    local dependency_graph
    if ! dependency_graph="$(cmd_go list -deps ./cmd/... ./internal/...)"; then
        echo "error: no se pudo construir el grafo de dependencias Go" >&2
        failed=1
    elif rg -x 'golang.org/x/crypto/openpgp' <<<"${dependency_graph}"; then
        echo "error: openpgp está en el grafo ejecutable; debe retirarse" >&2
        failed=1
    fi

    if [ "${failed}" -ne 0 ]; then
        exit 1
    fi
    echo "✅ Control de deuda técnica completado."
}

# Subcommand dispatch
case "${1:-}" in
    go)
        shift
        cmd_go "$@"
        ;;
    staticcheck)
        shift
        cmd_go_tool staticcheck "$@"
        ;;
    govulncheck)
        shift
        cmd_go_tool govulncheck "$@"
        ;;
    gofmt)
        shift
        cmd_go_tool gofmt "$@"
        ;;
    node)
        shift
        cmd_node node "$@"
        ;;
    npm)
        shift
        cmd_npm "$@"
        ;;
    npx)
        shift
        cmd_npx "$@"
        ;;
    promtool)
        shift
        cmd_promtool "$@"
        ;;
    syft)
        shift
        cmd_syft "$@"
        ;;
    shellcheck)
        shift
        cmd_shellcheck "$@"
        ;;
    audit)
        cmd_audit
        ;;
    debt)
        cmd_debt
        ;;
    build-images)
        cmd_build_images
        ;;
    *)
        echo "Uso: $0 {go|gofmt|staticcheck|govulncheck|node|npm|npx|promtool|syft|shellcheck|audit|debt|build-images} [argumentos...]"
        echo ""
        echo "Ejemplos:"
        echo "  $0 go test ./cmd/... ./internal/..."
        echo "  $0 go vet ./cmd/... ./internal/..."
        echo "  $0 staticcheck ./cmd/... ./internal/..."
        echo "  $0 govulncheck ./cmd/... ./internal/..."
        echo "  # Desde midori-vpn-desktop/agent, ./... sigue siendo un módulo aislado válido."
        echo "  $0 shellcheck scripts/pod.sh scripts/test-pod-runner.sh"
        echo "  $0 npm run check"
        echo "  $0 audit"

        echo "  $0 debt"
        exit 1
        ;;
esac
