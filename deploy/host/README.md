# Canonical host deployment

This directory is the supported host-side path for MidoriVPN 2.0.0. It does
not build software on a server. CI publishes private Core and Control images,
plus any enabled gateway image, and supplies immutable `registry/path@sha256:`
references. The renderer rejects tags, `latest`, Quadlet `.build` files and
automatic image updates.

The application profile runs rootless as a dedicated user. PostgreSQL, Redis,
PgBouncer, Core, Control, Prometheus and Grafana are reachable only through the
pod/private network or explicit loopback bindings. WireGuard and MASQUE are the
only public pod ports. OpenVPN and IKEv2 are optional rootful Quadlets because
they require host networking and narrowly scoped network capabilities.

Use [`docs/PRODUCTION_DEPLOYMENT.md`](../../docs/PRODUCTION_DEPLOYMENT.md) as the
operator runbook for protected Actions configuration, release order, first
installation, upgrades, recovery, rotation and the 2.0.0 availability boundary.
This file documents the individual host tools.

## 1. Prepare openSUSE

Inspect first, then apply through `sudo`:

```bash
sudo bash deploy/host/prepare-opensuse.sh --check --service-user midorivpn
sudo bash deploy/host/prepare-opensuse.sh --apply --service-user midorivpn
```

The apply operation installs Podman, Nginx, firewalld, SELinux utilities,
rootless networking helpers and the openSUSE Python 3.13 Certbot/Nginx packages.
It enables user linger and creates private directories. It deliberately does
not open firewall ports or issue a certificate: those actions depend on the
approved hostname and transport set. Once `.env` is complete, apply only the
declared public ingress (HTTP/HTTPS, WireGuard and enabled proxy/MASQUE):

```bash
sudo bash deploy/host/configure-firewall.sh \
  --env-file /home/midorivpn/.config/midorivpn/midorivpn.env \
  --apply
```

For rootless MASQUE, `MASQUE_PORT=443` remains the public and container port,
while `MASQUE_HOST_PORT=8443` is the non-privileged host bind. Firewalld owns
the exact UDP redirect. Database, Redis, Core HTTP, Control, Prometheus and
Grafana ports are never opened.

## 2. Patch configuration without replacing it

GitHub Actions or an operator writes only the values being changed to a private
temporary file. Do not upload or reconstruct the server's complete `.env`.

```bash
sudo -u midorivpn bash deploy/host/patch-env.sh \
  --env-file /home/midorivpn/.config/midorivpn/midorivpn.env \
  --values-file /run/user/$(id -u midorivpn)/midorivpn-release-values.env
```

Only keys in `managed-env-keys.txt` are accepted. Existing comments, ordering
and unmanaged values remain intact. The write and rename are atomic, mode 0600,
and an equally private timestamped backup is made whenever the file existed.
Secrets must be passed through a protected file or standard input redirection,
never command arguments or logs.

Restore the exact backup printed by the patcher if a later gate fails:

```bash
sudo -u midorivpn bash deploy/host/restore-env.sh \
  --env-file /home/midorivpn/.config/midorivpn/midorivpn.env \
  --backup-file /home/midorivpn/.config/midorivpn/backups/midorivpn.env.TIMESTAMP.bak
```

## 3. Render immutable Quadlets

Run rendering as the rootless service user so absolute environment paths match
that account:

```bash
sudo -u midorivpn bash deploy/host/render-quadlets.sh \
  --env-file /home/midorivpn/.config/midorivpn/midorivpn.env \
  --output-dir /home/midorivpn/.local/state/midorivpn-deploy/rendered-2.0.0 \
  --runtime-dir /home/midorivpn/.config/containers/systemd/midorivpn
```

The output contains a checksum manifest and separate 0600 environment files.
Database bootstrap credentials are visible only to PostgreSQL and the policy
steps; migration, runtime, PgBouncer and Grafana credentials remain isolated.
The dependency chain is PostgreSQL/Redis, role policy, migration, policy
verification, PgBouncer, Core, then Control. No database restore is automatic.

## 4. Install and validate

Install rootless units as the service user. Install `rootful/` separately via
`sudo` only when a gateway is enabled:

```bash
sudo -u midorivpn bash deploy/host/install-quadlets.sh \
  --bundle /home/midorivpn/.local/state/midorivpn-deploy/rendered-2.0.0

sudo bash deploy/host/install-quadlets.sh \
  --bundle /home/midorivpn/.local/state/midorivpn-deploy/rendered-2.0.0 \
  --scope rootful
```

Every installation verifies all hashes and rejects symlinks. It snapshots the
previous dedicated unit directory before replacement. A failed daemon reload or
startup restores the previous files, but never rewinds PostgreSQL or any other
data volume.

Configure Nginx as root after the Quadlets are healthy. Certificate issuance is
an explicit option, so a dry host preparation cannot accidentally consume ACME
limits:

```bash
sudo bash deploy/host/configure-nginx.sh \
  --env-file /home/midorivpn/.config/midorivpn/midorivpn.env

sudo bash deploy/host/configure-nginx.sh \
  --env-file /home/midorivpn/.config/midorivpn/midorivpn.env \
  --issue-certificate
```

The script renders `deploy/nginx/core-vhost.conf.template`, creates a private
snapshot, runs `nginx -t` and restores the former files on failure. Its exact
`/.well-known/midorivpn/edge-health` location prevents the Control SPA from
returning HTML for Desktop probes. Validate both local readiness and the public
contract:

```bash
sudo -u midorivpn bash deploy/host/healthcheck.sh \
  --core-url http://127.0.0.1:8085/readyz \
  --control-url http://127.0.0.1:5173/ \
  --edge-url https://vpn.example.com/.well-known/midorivpn/edge-health
```

The public response must be exactly HTTP 204, empty, non-HTML and include
`Cache-Control: no-store`. A generic 200 is a routing error and blocks rollout.
After the route passes, configure the server's `probe_url` through the
authenticated administrative API as the same exact HTTPS URL. Host automation
does not mutate Control inventory or infer which historical server row is safe
to adopt; the client candidates response and VAL-04 must verify it before
automatic selection is certified.

## 5. Configuration rollback

Use the snapshot path printed by the installer:

```bash
sudo -u midorivpn bash deploy/host/rollback.sh \
  --backup-dir /home/midorivpn/.local/state/midorivpn-deploy/backups/TIMESTAMP-rootless \
  --target-dir /home/midorivpn/.config/containers/systemd/midorivpn \
  --restart
```

Rollback changes unit/configuration files only and retains the displaced version
for inspection. Database recovery remains the separate, explicit and pretested
backup/restore procedure documented in `deploy/POSTGRESQL.md`.

## CI/CD handoff

The release workflow is tag-driven. It must build Core and Control, scan them,
push them to an authenticated private registry, resolve the registry-provided
digest, and transfer the scripts plus a small protected values file. GitHub
Actions variables provide non-secret configuration and Actions secrets provide
credentials. The remote job invokes `patch-env.sh`; it never substitutes the
whole `.env`. Deployment remains blocked until image signatures, SBOM,
provenance, Nginx validation, database backup/restore gate and this healthcheck
all pass. External publication and production rollout require separate explicit
authorization.

The exact Actions contract is versioned in
`deploy/ci/environment-map.json`. Non-secret dotenv entries arrive through the
`MIDORIVPN_DEPLOY_VALUES` Environment variable; sensitive entries arrive only
through the `MIDORIVPN_DEPLOY_SECRETS` Environment secret. The validator rejects
wrongly classified, duplicated or unknown keys, and the verified workflow
injects `CORE_IMAGE` and `CONTROL_IMAGE` by digest itself. SSH private key,
pinned known-hosts material and the read-only GHCR token are separate protected
secrets. The remote orchestrator performs a database backup plus isolated
restore gate when PostgreSQL already exists and never restores live data
automatically.
