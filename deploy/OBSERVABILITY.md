# Private observability

MidoriVPN uses Prometheus 3.14 and Grafana 13 for private operational metrics.
It deliberately does not collect user identities, client addresses, requested
destinations or per-user traffic. Loki and distributed tracing are outside the
2.0.0 scope.

Prometheus scrapes Core by its DNS name on the private Podman application
network. Grafana reaches Prometheus on that same network. They remain
independent rootless Quadlet services and publish their administrative ports
only on `127.0.0.1`; they do not rely on the host gateway to bypass Core's
loopback boundary. The public Nginx vhost must continue returning `404` for
`/metrics`. Reach Grafana through an SSH tunnel when administration is
required; do not add a public Nginx location.

## Render and install

Set the observability variables in the private deployment environment. Images
must include immutable `@sha256:` digests. The renderer creates a dedicated
Grafana environment containing only its two credentials; it never passes the
Core environment or its secrets to either observability container.
Rendered YAML/JSON is `0644` inside a host directory restricted to `0700` so
the non-root image users can read bind-mounted configuration. Only
`grafana.env` contains a secret and remains `0600`; Podman reads it on the host.
`OBSERVABILITY_NETWORK` names the existing private Core network and
`VPN_CORE_METRICS_TARGET` names Core inside it, for example
`midori-control:8085`. The renderer rejects host URLs and arbitrary target
syntax.

```bash
ENV_FILE=/secure/midori-control.env bash scripts/render-observability.sh
bash scripts/check-observability.sh

OBSERVABILITY_CONFIG_DIR="$OBSERVABILITY_CONFIG_DIR" \
QUADLET_DIR="$HOME/.config/containers/systemd/midori-control" \
CORE_IMAGE="localhost/midori-vpn-core:<verified-staging-tag>" \
  bash scripts/deploy-observability.sh
```

The deployer backs up the Core Quadlet, changes its image only when required,
regenerates the observability units and health-gates all three services. A
failed first deployment removes the incomplete observability units and restores
the prior Core image.

Quadlet units are generated units and must not be passed to `systemctl enable`.
Their `[Install]` sections provide boot activation when the user manager is
regenerated; user lingering must remain enabled on the server.
The first Grafana start can spend several minutes applying its embedded SQLite
migrations on a busy host. SQLite WAL is enabled and the deployment health gate
allows fifteen minutes by default only for that initialization; it remains
configurable through `GRAFANA_STARTUP_ATTEMPTS` and still rolls back if the API
never becomes ready.

Example local access from an administrator workstation:

```bash
ssh -N -L 3000:127.0.0.1:${GRAFANA_HOST_PORT} Main
```

Then open `http://127.0.0.1:3000`. Prometheus alert rules are visible through
the provisioned data source. Notification destinations are operational secrets
and must be configured in Grafana, not committed to this repository.

## Multi-cluster extension

The principal deployment is the only currently deployed target. The regional
contract is defined in
[`docs/CENTRAL_CONTROL_ARCHITECTURE.md`](../docs/CENTRAL_CONTROL_ARCHITECTURE.md):
central Prometheus scrapes regional Core targets over an authenticated private
management network. Never publish a regional `/metrics` listener to the
Internet merely to make central scraping possible.
