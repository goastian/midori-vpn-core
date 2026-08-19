#!/usr/bin/env bash
set -e

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

# Image Names
IMAGE_GO="localhost/midori-dev-go:latest"
IMAGE_NODE="localhost/midori-dev-node:latest"
IMAGE_TAURI="localhost/midori-dev-tauri:latest"

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
    podman run --rm -it \
        --userns=keep-id \
        -v "${ROOT_DIR}:/workspace:z" \
        -v midori_go_pkg:/go/pkg:z \
        -v midori_go_cache:/tmp/go-cache:z \
        -e GOCACHE=/tmp/go-cache \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_GO}" go "$@"
}

cmd_node() {
    build_image_if_missing "${IMAGE_NODE}" "${ROOT_DIR}/midori-vpn-control/.container/Containerfile" "${ROOT_DIR}/midori-vpn-control"
    podman run --rm -it \
        --userns=keep-id \
        -v "${ROOT_DIR}:/workspace:z" \
        -v midori_npm_cache:/tmp/npm-cache:z \
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

cmd_tauri() {
    build_image_if_missing "${IMAGE_TAURI}" "${ROOT_DIR}/midori-vpn-desktop/.container/Containerfile" "${ROOT_DIR}/midori-vpn-desktop"
    podman run --rm -it \
        --userns=keep-id \
        -v "${ROOT_DIR}:/workspace:z" \
        -v midori_cargo_registry:/usr/local/cargo/registry:z \
        -v midori_cargo_git:/usr/local/cargo/git:z \
        -v midori_npm_cache:/tmp/npm-cache:z \
        -e npm_config_cache=/tmp/npm-cache \
        -w "${WORKDIR_IN_CONTAINER}" \
        "${IMAGE_TAURI}" "$@"
}

cmd_cargo() {
    cmd_tauri cargo "$@"
}

cmd_audit() {
    echo "🛡️ [1/3] Ejecutando govulncheck en Core y Agente..."
    build_image_if_missing "${IMAGE_GO}" "${ROOT_DIR}/.container/Containerfile" "${ROOT_DIR}"
    podman run --rm -it \
        --userns=keep-id \
        -v "${ROOT_DIR}:/workspace:z" \
        -w "/workspace" \
        "${IMAGE_GO}" govulncheck ./... || true

    echo "🛡️ [2/3] Ejecutando npm audit en Frontends..."
    build_image_if_missing "${IMAGE_NODE}" "${ROOT_DIR}/midori-vpn-control/.container/Containerfile" "${ROOT_DIR}/midori-vpn-control"
    for d in midori-vpn-control midorivpn-extension midori-vpn-desktop; do
        if [ -d "${ROOT_DIR}/${d}" ]; then
            echo " → Auditando ${d}..."
            podman run --rm -it \
                --userns=keep-id \
                -v "${ROOT_DIR}:/workspace:z" \
                -w "/workspace/${d}" \
                "${IMAGE_NODE}" npm audit --audit-level=high || true
        fi
    done

    echo "🛡️ [3/3] Ejecutando cargo-audit en Tauri..."
    build_image_if_missing "${IMAGE_TAURI}" "${ROOT_DIR}/midori-vpn-desktop/.container/Containerfile" "${ROOT_DIR}/midori-vpn-desktop"
    podman run --rm -it \
        --userns=keep-id \
        -v "${ROOT_DIR}:/workspace:z" \
        -w "/workspace/midori-vpn-desktop/src-tauri" \
        "${IMAGE_TAURI}" cargo audit || true
    
    echo "✅ Auditoría de seguridad completada."
}

# Subcommand dispatch
case "$1" in
    go)
        shift
        cmd_go "$@"
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
    build-images)
        cmd_build_images
        ;;
    *)
        echo "Uso: $0 {go|node|npm|npx|tauri|cargo|audit|build-images} [argumentos...]"
        echo ""
        echo "Ejemplos:"
        echo "  $0 go test ./..."
        echo "  $0 go vet ./..."
        echo "  $0 npm run check"
        echo "  $0 tauri cargo test"
        echo "  $0 audit"
        exit 1
        ;;
esac
