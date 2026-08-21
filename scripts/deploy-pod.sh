#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Midori VPN — Podman Pod Production & Staging Deployment Script
# ==============================================================================

POD_NAME="midori-vpn-pod"
ENV_FILE="${ENV_FILE:-.env}"

if [ ! -f "${ENV_FILE}" ]; then
  echo "❌ Error: Archivo de entorno ${ENV_FILE} no encontrado."
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

echo "🚀 Iniciando despliegue de Midori VPN Pod (${POD_NAME})..."

if podman pod exists "${POD_NAME}" 2>/dev/null; then
  echo "🧹 Deteniendo y eliminando pod anterior..."
  podman pod rm -f "${POD_NAME}"
fi

echo "📦 Creando Podman Pod '${POD_NAME}'..."
podman pod create \
  --name "${POD_NAME}" \
  -p "${WG_PORT:-51820}:${WG_PORT:-51820}/udp" \
  -p "127.0.0.1:${VPN_CORE_HOST_PORT:-8085}:${VPN_CORE_PORT:-8085}/tcp" \
  -p "127.0.0.1:${CONTROL_HOST_PORT:-5173}:80/tcp"

echo "🐘 Iniciando midori-postgres..."
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-postgres \
  --restart always \
  -e POSTGRES_USER="${POSTGRES_USER:-midori}" \
  -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD requerida}" \
  -e POSTGRES_DB="${POSTGRES_DB:-midori_vpn}" \
  -v midori-pgdata:/var/lib/postgresql/data:Z \
  docker.io/library/postgres:18-alpine

echo "⚡ Iniciando midori-redis..."
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-redis \
  --restart always \
  -v midori-redisdata:/data:Z \
  docker.io/library/redis:7-alpine redis-server --requirepass "${REDIS_PASSWORD:-midori-redis}"

echo "⏳ Esperando arranque de PostgreSQL..."
sleep 3

echo "🛡️ Iniciando midori-vpn-core..."
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-vpn-core \
  --restart always \
  --cap-drop=ALL \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --env-file "${ENV_FILE}" \
  -v wg-config:/etc/wireguard:Z \
  localhost/midori-vpn-core:local

echo "🖥️ Iniciando midori-vpn-control..."
podman run -d \
  --pod "${POD_NAME}" \
  --name midori-vpn-control \
  --restart always \
  localhost/midori-vpn-control:local

echo "✅ ¡Despliegue del Podman Pod completado exitosamente!"
podman pod ps --filter "name=${POD_NAME}"
