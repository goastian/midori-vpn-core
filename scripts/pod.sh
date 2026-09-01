#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================================================================
# Midori VPN — Podman Rootless Unified Runner
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CURRENT_DIR="$(pwd)"

# Calculate relative path from ROOT_DIR to current directory
if [[ "${CURRENT_DIR}" == "${ROOT_DIR}"* ]]; then
    REL_PATH="${CURRENT_DIR#$ROOT_DIR}"
    REL_PATH="${REL_PATH#/}"
else
    REL_PATH=""
fi

WORKDIR_IN_CONTAINER="/workspace/${REL_PATH}"
NODE_MODULES_VOLUME="midori_npm_modules_${REL_PATH//\//_}"
if [[ -z "${REL_PATH}" ]]; then
    NODE_MODULES_VOLUME="midori_npm_modules_root"
fi

# Image Names
IMAGE_GO="localhost/midori-dev-go:latest"
IMAGE_NODE="localhost/midori-dev-node:latest"
IMAGE_TAURI="localhost/midori-dev-tauri:latest"
IMAGE_PROMETHEUS="docker.io/prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
PODMAN_USERNS=(--userns=keep-id:uid=0,gid=0)

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
    echo "🔨 Construyendo todas las imágenes de desarrollo Podman Rootless..."
    podman build -t "${IMAGE_GO}" -f "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman build -t "${IMAGE_NODE}" -f "${ROOT_DIR}/midori-vpn-control/.container/Containerfile" "${ROOT_DIR}/midori-vpn-control"
    podman build -t "${IMAGE_TAURI}" -f "${ROOT_DIR}/midori-vpn-desktop/.container/Containerfile" "${ROOT_DIR}/midori-vpn-desktop"
    echo "✅ Todas las imágenes construidas exitosamente."
}

cmd_go() {
    build_image_if_missing "${IMAGE_GO}" "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman run --rm "${PODMAN_USERNS[@]}" \
        -v "${ROOT_DIR}:/workspace:z" \
        -v midori_go_pkg:/go/pkg:z \
        -v midori_go_cache:/tmp/go-cache:z \
        -e GOCACHE=/tmp/go-cache \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_GO}" go "$@"
}

cmd_go_tool() {
    local tool="$1"
    shift
    build_image_if_missing "${IMAGE_GO}" "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman run --rm "${PODMAN_USERNS[@]}" \
        -v "${ROOT_DIR}:/workspace:z" \
        -v midori_go_pkg:/go/pkg:z \
        -v midori_go_cache:/tmp/go-cache:z \
        -e GOCACHE=/tmp/go-cache \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_GO}" "${tool}" "$@"
}

cmd_node() {
    build_image_if_missing "${IMAGE_NODE}" "${ROOT_DIR}/midori-vpn-control/.container/Containerfile" "${ROOT_DIR}/midori-vpn-control"
    podman run --rm "${PODMAN_USERNS[@]}" \
        -v "${ROOT_DIR}:/workspace:z" \
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
        -v "${ROOT_DIR}:/workspace:z" \
        -w "${WORKDIR_IN_CONTAINER}" \
        --entrypoint /bin/promtool \
        "${IMAGE_PROMETHEUS}" "$@"
}

cmd_tauri() {
    build_image_if_missing "${IMAGE_TAURI}" "${ROOT_DIR}/midori-vpn-desktop/.container/Containerfile" "${ROOT_DIR}/midori-vpn-desktop"
    podman run --rm "${PODMAN_USERNS[@]}" \
        -v "${ROOT_DIR}:/workspace:z" \
        -v midori_cargo_registry:/usr/local/cargo/registry:z \
        -v midori_cargo_git:/usr/local/cargo/git:z \
        -v midori_cargo_target:/tmp/cargo-target:z \
        -v midori_npm_cache:/tmp/npm-cache:z \
        -v "${NODE_MODULES_VOLUME}:${WORKDIR_IN_CONTAINER}/node_modules:z" \
        -e CARGO_TARGET_DIR=/tmp/cargo-target \
        -e npm_config_cache=/tmp/npm-cache \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_TAURI}" "$@"
}

cmd_cargo() {
    cmd_tauri cargo "$@"
}

cmd_audit() {
    echo "🛡️ [1/4] Ejecutando govulncheck en Core y Agente..."
    build_image_if_missing "${IMAGE_GO}" "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman run --rm "${PODMAN_USERNS[@]}" \
        -v "${ROOT_DIR}:/workspace:z" \
        -w "/workspace" \
        "${IMAGE_GO}" govulncheck ./cmd/... ./internal/...

    podman run --rm "${PODMAN_USERNS[@]}" \
        -v "${ROOT_DIR}:/workspace:z" \
        -w "/workspace/midori-vpn-desktop/agent" \
        "${IMAGE_GO}" govulncheck ./...

    echo "🛡️ [2/4] Ejecutando npm audit en Frontends..."
    build_image_if_missing "${IMAGE_NODE}" "${ROOT_DIR}/midori-vpn-control/.container/Containerfile" "${ROOT_DIR}/midori-vpn-control"
    for d in midori-vpn-control midorivpn-extension midori-vpn-desktop; do
        if [ -d "${ROOT_DIR}/${d}" ]; then
            echo " → Auditando ${d}..."
            podman run --rm "${PODMAN_USERNS[@]}" \
                -v "${ROOT_DIR}:/workspace:z" \
                -w "/workspace/${d}" \
                "${IMAGE_NODE}" npm audit --audit-level=high
        fi
    done

    echo "🛡️ [3/4] Ejecutando cargo-audit en Tauri..."
    build_image_if_missing "${IMAGE_TAURI}" "${ROOT_DIR}/midori-vpn-desktop/.container/Containerfile" "${ROOT_DIR}/midori-vpn-desktop"
    podman run --rm "${PODMAN_USERNS[@]}" \
        -v "${ROOT_DIR}:/workspace:z" \
        -w "/workspace/midori-vpn-desktop/src-tauri" \
        "${IMAGE_TAURI}" cargo audit --deny warnings

    echo "🛡️ [4/4] Validando los lockfiles de Rust..."
    podman run --rm "${PODMAN_USERNS[@]}" \
        -v "${ROOT_DIR}:/workspace:z" \
        -w "/workspace/midori-vpn-desktop/src-tauri" \
        "${IMAGE_TAURI}" cargo check --locked
    
    echo "✅ Auditoría de seguridad completada."
}

cmd_debt() {
    local markers='\b(TODO|FIXME|HACK|XXX|DEPRECATED|OBSOLETE|LEGACY)\b'
    local failed=0

    echo "🧹 [1/3] Buscando marcadores obsoletos en código vivo..."
    if rg -n -e "${markers}" \
        --glob '*.{go,rs,ts,tsx,vue,js,mjs,cjs,sh,sql}' \
        --glob '!node_modules/**' --glob '!dist/**' --glob '!.git/**' \
        --glob '!scripts/pod.sh' \
        "${ROOT_DIR}/cmd" "${ROOT_DIR}/internal" \
        "${ROOT_DIR}/scripts" "${ROOT_DIR}/midori-vpn-control/src" \
        "${ROOT_DIR}/midori-vpn-desktop" "${ROOT_DIR}/midorivpn-extension/src"; then
        echo "error: se encontraron marcadores prohibidos de deuda técnica" >&2
        failed=1
    fi

    echo "🧹 [2/3] Verificando pares de migración..."
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

    echo "🧹 [3/3] Confirmando que openpgp no está en el grafo ejecutable..."
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
case "$1" in
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
    tauri)
        shift
        cmd_tauri "$@"
        ;;
    cargo)
        shift
        cmd_cargo "$@"
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
        echo "Uso: $0 {go|gofmt|staticcheck|govulncheck|node|npm|npx|promtool|tauri|cargo|audit|debt|build-images} [argumentos...]"
        echo ""
        echo "Ejemplos:"
        echo "  $0 go test ./..."
        echo "  $0 go vet ./..."
        echo "  $0 staticcheck ./..."
        echo "  $0 govulncheck ./..."
        echo "  $0 npm run check"
        echo "  $0 tauri cargo test"
        echo "  $0 audit"

        echo "  $0 debt"
        exit 1
        ;;
esac
