# Canonical host deployment

This directory is the supported host-side path for MidoriVPN 2.0.0. It does
not build software on a server. CI publishes private Core and Control images,
plus any enabled gateway image, and supplies complete
`registry/path:major.minor.patch[-prerelease]` references. The renderer rejects
digests as runtime references, missing or moving tags such as `latest`, Quadlet
`.build` files and automatic image updates. CI still records the resolved digest
for verification, evidence and rollback.

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

The apply operation installs Podman, Nginx, firewalld, SELinux utilities and
rootless networking helpers plus `wireguard-tools`. It preserves an existing `certbot` installation
when its Nginx plugin is functional; otherwise it selects the native Certbot
packages for Leap or Tumbleweed. It verifies a subordinate UID/GID range of at
least 65,536 IDs, Podman Quadlet, user linger and private directories. It
deliberately does not open firewall ports or issue a certificate: those actions
depend on the approved hostname and transport set. The service account name is
operator-selectable; use the same value in every subsequent command. Once
`.env` is complete, apply only the declared public ingress (HTTP/HTTPS,
WireGuard and enabled proxy/MASQUE):

```bash
sudo bash deploy/host/configure-firewall.sh \
  --env-file /home/midorivpn/.config/midorivpn/midorivpn.env \
  --apply
```

### Dedicated management overlay

Create the management link before enrollment or application activation. It is
a host-level WireGuard interface named `mvpn-mgmt`; it is not the customer VPN.
Main owns `10.254.240.1/32`, the regional owns `10.254.240.2/32`, and each peer
accepts only the other `/32`. There is no forwarding, NAT, default route or LAN
route. The regional listens on one random high UDP port and Main initiates with
`PersistentKeepalive=25`.

On the regional, generate the two unrelated public transport values once:

```bash
sudo bash deploy/host/generate-network-values.sh
```

Store the resulting management UDP port, customer UDP port and opaque
32-hexadecimal customer endpoint label in the protected inventory. Confirm both
ports are unused on the regional. The customer endpoint DNS record is DNS-only;
Cloudflare cannot proxy raw WireGuard UDP.

Prepare host identities without printing private material:

```bash
sudo bash deploy/host/configure-management-wireguard.sh --prepare --role principal
sudo bash deploy/host/configure-management-wireguard.sh --prepare --role regional
```

Exchange only `public.key`. Transfer the principal's `preshared.key` once over
an authenticated encrypted channel into the regional's private state directory;
never put it in Git, Actions variables or logs. After recording an independent
approval for each host, apply the regional first and Main second:

```bash
sudo bash deploy/host/configure-management-wireguard.sh \
  --apply --role regional --listen-port PORT \
  --peer-public-key-file /root/main-public.key \
  --preshared-key-file /etc/wireguard/mvpn-mgmt/preshared.key

sudo bash deploy/host/configure-management-wireguard.sh \
  --apply --role principal --listen-port PORT \
  --endpoint REGIONAL_PUBLIC_IP:PORT \
  --peer-public-key-file /root/regional-public.key \
  --preshared-key-file /etc/wireguard/mvpn-mgmt/preshared.key
```

The installer creates a dedicated firewalld zone: TCP/8443 is management TLS,
regional TCP/9443 is observability mTLS, and only the regional exposes the
management UDP port publicly. Validate an authenticated handshake and peer ping
on each host with `--check`. Rollback removes only the service, generated
configuration and firewall rules; it deliberately retains cryptographic keys:

```bash
sudo bash deploy/host/configure-management-wireguard.sh --check --role principal
sudo bash deploy/host/rollback-management-wireguard.sh regional PORT public
```

Generate the private management CA on an offline administrative machine:

```bash
bash deploy/host/generate-management-pki.sh /absolute/new/private-directory
```

Run it from the machine's local console after disconnecting all network links;
the interactive passphrase never crosses SSH. The generated `ca.key` is
encrypted with AES-256-CBC. Keep it offline and store its passphrase separately.
Each host receives `ca.crt` and only its matching certificate/key.
`configure-nginx.sh` adds a TLS-1.3-only listener bound to the host's overlay
address. On Main it exposes only `/api/v1/node/`; on the regional it exposes
only Core health, peer and stats routes. The application trusts this CA only
through `MANAGEMENT_TLS_CA`; it never modifies system-wide trust.

When the public vhosts are already managed independently, render or install
only the private listener. This mode never renders, replaces or requests a
certificate for a public vhost:

```bash
bash deploy/host/configure-nginx.sh \
  --env-file /path/to/midorivpn.env \
  --management-only \
  --render-only /absolute/new/review-directory

sudo bash deploy/host/configure-nginx.sh \
  --env-file /path/to/midorivpn.env \
  --management-only
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

The script renders the public vhost plus the profile-specific private management
vhost, creates a private
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
push them to an authenticated private registry, pull by exact version tag,
resolve the registry-provided digest, and transfer the scripts, runtime image
lock plus a small protected values file. GitHub
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
injects the exact tagged `CORE_IMAGE` and `CONTROL_IMAGE` references itself.
The host pulls those tags and compares every resolved digest with the protected
runtime lock before installing. SSH private key,
pinned known-hosts material and the read-only GHCR token are separate protected
secrets. The remote orchestrator performs a database backup plus isolated
restore gate when PostgreSQL already exists and never restores live data
automatically.
