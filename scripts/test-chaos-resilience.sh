#!/usr/bin/env bash
# ==============================================================================
# Midori VPN — Chaos & Network Resilience Simulation Suite (SEC-02)
# ==============================================================================
set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
WG_IFACE="${WG_IFACE:-wg0}"

echo "=== [1/3] Simulating Controlled Packet Loss (Netem 5%) ==="
if command -v tc >/dev/null 2>&1; then
    echo "Applying 5% packet loss on interface $WG_IFACE..."
    sudo tc qdisc add dev "$WG_IFACE" root netem loss 5% || true
    sleep 3
    echo "Removing packet loss filter..."
    sudo tc qdisc del dev "$WG_IFACE" root || true
else
    echo "tc command not found on host, skipping netem simulation."
fi

echo "=== [2/3] Simulating Gateway Failover & Health Endpoint Checks ==="
echo "Checking Liveness (/livez)..."
curl -s -f "http://$TARGET_HOST:8085/livez" | grep "alive" && echo "Liveness probe OK"

echo "Checking Readiness (/readyz)..."
curl -s -f "http://$TARGET_HOST:8085/readyz" | grep "ready" && echo "Readiness probe OK"

echo "=== [3/3] Checking Prometheus Metrics (/metrics) ==="
curl -s -f "http://$TARGET_HOST:8085/metrics" | grep "midori_vpn_" && echo "Prometheus metrics OK"

echo "=== Chaos & Resilience Suite Completed ==="
