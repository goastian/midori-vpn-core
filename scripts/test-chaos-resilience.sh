#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v podman >/dev/null 2>&1 || die "podman is required"
: "${LIVEZ_URL:?LIVEZ_URL is required}"
: "${READYZ_URL:?READYZ_URL is required}"
: "${METRICS_URL:?METRICS_URL is required and must target the private Core listener}"
: "${CHAOS_CONTAINER:?CHAOS_CONTAINER is required}"
: "${CHAOS_INTERFACE:?CHAOS_INTERFACE is required}"

[[ "$LIVEZ_URL" == https://* || "$LIVEZ_URL" == http://127.0.0.1:* || "$LIVEZ_URL" == http://localhost:* ]] || die "LIVEZ_URL must use HTTPS or loopback HTTP"
[[ "$READYZ_URL" == https://* || "$READYZ_URL" == http://127.0.0.1:* || "$READYZ_URL" == http://localhost:* ]] || die "READYZ_URL must use HTTPS or loopback HTTP"
[[ "$METRICS_URL" == http://127.0.0.1:* || "$METRICS_URL" == http://localhost:* ]] || die "METRICS_URL must remain on loopback"
[[ "$CHAOS_INTERFACE" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || die "CHAOS_INTERFACE is invalid"

packet_loss_percent="${PACKET_LOSS_PERCENT:-5}"
duration_seconds="${CHAOS_DURATION_SECONDS:-5}"
if ! [[ "$packet_loss_percent" =~ ^[0-9]+$ ]] || (( packet_loss_percent < 1 || packet_loss_percent > 20 )); then
  die "PACKET_LOSS_PERCENT must be between 1 and 20"
fi
if ! [[ "$duration_seconds" =~ ^[0-9]+$ ]] || (( duration_seconds < 3 || duration_seconds > 30 )); then
  die "CHAOS_DURATION_SECONDS must be between 3 and 30"
fi

podman container exists "$CHAOS_CONTAINER" || die "chaos target container does not exist"
[[ "$(podman inspect --format '{{.State.Running}}' "$CHAOS_CONTAINER")" == "true" ]] || die "chaos target container is not running"
podman exec "$CHAOS_CONTAINER" tc qdisc show dev "$CHAOS_INTERFACE" | grep -Eq '^qdisc (noqueue|mq) ' || die "interface already has a non-default root qdisc"

netem_active=false
cleanup() {
  if [[ "$netem_active" == true ]]; then
    podman exec "$CHAOS_CONTAINER" tc qdisc del dev "$CHAOS_INTERFACE" root >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

probe_services() {
  local phase="$1"
  curl --fail --silent --show-error --max-time 5 "$LIVEZ_URL" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"alive"' || die "$phase liveness probe failed"
  curl --fail --silent --show-error --max-time 5 "$READYZ_URL" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ready"' || die "$phase readiness probe failed"
  curl --fail --silent --show-error --max-time 5 "$METRICS_URL" | grep -q '^midori_vpn_' || die "$phase private metrics probe failed"
  printf '%s probes passed.\n' "$phase"
}

probe_services "Baseline"
podman exec "$CHAOS_CONTAINER" tc qdisc add dev "$CHAOS_INTERFACE" root netem loss "${packet_loss_percent}%"
netem_active=true
printf 'Applied %s%% packet loss to %s for %ss.\n' "$packet_loss_percent" "$CHAOS_INTERFACE" "$duration_seconds"
sleep "$duration_seconds"
probe_services "Degraded-network"
podman exec "$CHAOS_CONTAINER" tc qdisc del dev "$CHAOS_INTERFACE" root
netem_active=false
probe_services "Recovery"
printf 'Packet-loss and recovery validation passed.\n'
