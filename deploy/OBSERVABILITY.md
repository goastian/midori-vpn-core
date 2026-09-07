# Private observability

MidoriVPN uses Prometheus 3.14 and Grafana 13.2 for private operational metrics.
It deliberately does not collect user identities, client addresses, requested
destinations or per-user traffic. Loki and distributed tracing are outside the
2.0.0 scope.

Every Core exposes metrics and, on the principal only, HTTP service discovery
through a dedicated listener on TCP/9443. The listener accepts TLS 1.3 only,
requires a client certificate issued by its private observability client CA and
then requires the exact configured SPIFFE URI SAN. It is not part of the public
Core router or OpenAPI contract.

Prometheus reaches the principal Core by its private Podman DNS name and
discovers regional targets from `/api/v1/observability/targets`. Discovery
returns only nodes belonging to operational clusters and having an operational
node lifecycle state. Stale active nodes remain targets deliberately so a
failed scrape and stale heartbeat can alert; enrolling, inactive, revoked and
retired nodes are excluded. Regional targets use their validated private
management address and the fixed port 9443.

Grafana reaches Prometheus on the private Podman network. Both remain
independent rootless Quadlet services and publish their administrative ports
only on `127.0.0.1`. The public Nginx vhost must continue returning `404` for
`/metrics`. Reach Grafana through an SSH tunnel when administration is
required; do not add a public Nginx location.

## Render and install

Set the observability variables in the private deployment environment. Images
must include complete, non-moving version tags. The renderer creates a dedicated
Grafana environment containing only its two credentials; it never passes the
Core environment or its secrets to either observability container.
Rendered YAML/JSON is `0644` inside a host directory restricted to `0700`.
Only `grafana.env` and the Prometheus client private key contain secrets and
remain `0600`; Podman reads or mounts them from the host. Prometheus runs as
container UID 0 solely so it can read that key inside its rootless user
namespace. The container remains unprivileged, read-only, without capabilities
or new privileges.
`OBSERVABILITY_NETWORK` names the existing private Core network and
`VPN_CORE_METRICS_TARGET` names Core inside it, for example
`midori-control:9443`. The renderer rejects host URLs, arbitrary target syntax,
symlinks and a client key not owned with mode `0600`.

Use separate operational roles even when one offline CA hierarchy issues both:

- each Core receives its own server certificate and private key plus the public
  client-CA certificate;
- Prometheus receives its client certificate and private key plus the public
  server-CA certificate;
- regional nodes never receive the Prometheus client key, either CA signing
  key, PostgreSQL, Authentik, the client-VPN CA or a Control private key;
- the URI SAN must equal `OBSERVABILITY_ALLOWED_CLIENT_URI` exactly; DNS/common
  name fallback is not accepted for client authorization.

```bash
ENV_FILE=/secure/midori-control.env bash scripts/render-observability.sh
bash scripts/check-observability.sh

OBSERVABILITY_CONFIG_DIR="$OBSERVABILITY_CONFIG_DIR" \
QUADLET_DIR="$HOME/.config/containers/systemd/midori-control" \
CORE_IMAGE="localhost/midori-vpn-core:<verified-staging-tag>" \
  bash scripts/deploy-observability.sh
```

The deployer backs up the Core Quadlet, changes its image only when required,
regenerates the observability units and health-gates all three services. It
also requires the principal Core target to reach `up=1`; Prometheus readiness
alone is not accepted as evidence that network, CA, certificate mounts and the
authorized URI are correct. A failed first deployment removes the incomplete
observability units and restores the prior Core image.

Quadlet units are generated units and must not be passed to `systemctl enable`.
Their `[Install]` sections provide boot activation when the user manager is
regenerated; user lingering must remain enabled on the server.
The first Grafana start can spend several minutes applying its embedded SQLite
migrations on a busy host. SQLite WAL is enabled and the deployment health gate
allows fifteen minutes by default only for that initialization; it remains
configurable through `GRAFANA_STARTUP_ATTEMPTS` and still rolls back if the API
never becomes ready. The read-only container also disables automatic updates of
bundled plugins; plugin versions come exclusively from the digest-pinned image,
so startup never tries to mutate `/usr/share/grafana`.

Example local access from an administrator workstation:

```bash
ssh -N -L 3000:127.0.0.1:${GRAFANA_HOST_PORT} principal.example.net
```

Then open `http://127.0.0.1:3000`. Prometheus alert rules are visible through
the provisioned data source. Notification destinations are operational secrets
and must be configured in Grafana, not committed to this repository.

The reconciliation and fleet panels use aggregate gauges only:
`midori_vpn_reconciliation_divergent_peers`,
`midori_vpn_reconciliation_cleanup_pending`,
`midori_vpn_peer_operations_pending` and
`midori_vpn_reconciliation_observation_errors`, plus node heartbeat age,
desired/observed convergence, version compatibility, desired-signature error,
capacity and bounded signed-auth failure counters. A failed Core observation is
reported separately and never interpreted as zero peers. Labels are limited to
cluster, node, lifecycle/health state and bounded failure reason. No series
contains a peer key, operation UUID, user, client address, device or destination.

## Certificate rotation

Install overlapping trust before rotating a CA or client identity. Issue and
deploy the replacement server certificates to every Core, update Prometheus
trust, and prove all targets `up` before removing the prior server CA. For the
client side, add the replacement client CA to every Core trust bundle, deploy a
new Prometheus certificate with the same authorized URI SAN, prove principal
discovery and all scrapes, then remove the old client CA. A failed rotation
keeps the prior certificates and trust bundle; never disable client
verification or lower TLS to recover a target.

## Multi-cluster extension

The private fleet contract is implemented on the principal, which remains the
only certified deployment target. The regional contract is defined in
[`docs/CENTRAL_CONTROL_ARCHITECTURE.md`](../docs/CENTRAL_CONTROL_ARCHITECTURE.md):
the regional deployer requires an exact RFC1918 bind for TCP/9443, while the
principal permits access only through its private Podman network. The first
real gate must use a new server and leave the existing principal in place. Never publish
a regional observability listener to the Internet merely to make central
scraping possible.
