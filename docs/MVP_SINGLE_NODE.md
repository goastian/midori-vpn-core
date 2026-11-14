# Single-node limited-beta profile

The initial beta scope is one principal with a local Core, Linux Desktop over
WireGuard, and the Firefox/Midori and Chromium extension over authenticated
HTTPS CONNECT. Both clients are required. WSS, MASQUE, OpenVPN DCO, IKEv2 and
additional nodes/failover are deferred, not removed or certified. This profile
does not offer high availability. A browser proxy is not a system-wide VPN.

This document defines a deployment scope, **not a release or activation**.
MidoriVPN remains unreleased. A healthy process or successful render is not
evidence of working tunnels, isolation or client acceptance.

## Reuse the existing deployment path

Use `deploy/host/` and its `principal` deployment profile. Do not create another
deployer or weaken the signed node enrollment, observation, desired-state lease,
placement, transport health or central certification checks for a single node.

Fill the complete `.env.example` with reviewed deployment values. The renderer
still requires private management TLS and an overlay address pair in production.
**Do not invent a second host, reuse an unrelated management overlay, or bypass
these checks.** The local node's authenticated management/enrollment path must be
resolved and verified before the first operational deployment. This preset does
not solve that topology requirement.

The standard principal renderer provisions its own private PostgreSQL/PgBouncer
pod. On a shared host, decide storage integration explicitly before deploying;
this preset does not authorize modifying an existing database service or
silently replacing the project's database security policy. Keep migration,
runtime, owner, backup and pooler-administrator identities separate.

## Explicit transport configuration

`deploy/mvp/wireguard-proxy.env.example` contains only transport settings. It
must be merged as data with the existing patcher, never sourced as shell code:

```bash
bash deploy/host/patch-env.sh \
  --env-file /path/to/private/midorivpn.env \
  --values-file deploy/mvp/wireguard-proxy.env.example
```

Patching changes a file and requires operator approval on the destination host.
It neither enables services nor updates the database transport inventory. The
complete environment must also supply the local server/cluster UUIDs, endpoints,
ports, OIDC configuration, signing trust, database credentials and private
observability configuration. Do not copy test fixtures into production.

The preset chooses the existing Nginx stream TLS-termination path:

- `PROXY_ENABLED=true`, `PROXY_TLS_ENABLED=false` and
  `PROXY_TLS_TERMINATED_BY_NGINX=true`.
- `PROXY_PORT` is both the Core container port and the public stream port;
  `PROXY_HOST_PORT` is a **different, unused loopback backend port**.
- Nginx stream terminates TLS and forwards raw CONNECT traffic to that backend.
  A normal HTTP reverse-proxy location is not a forward proxy.
- Ensure the stream module is loaded when built dynamically and that the
  generated file is included inside a top-level `stream {}` context, not the
  shared HTTP vhost directory. Review and syntax-test the complete host config
  before a separately approved reload; do not replace existing HTTPS services.
- This Nginx template requires an unencrypted loopback CONNECT backend. It
  rejects direct Core TLS rather than silently introducing a second TLS layer.
- Use a direct/DNS-only hostname covered by the certificate. Do not route
  CONNECT through a CDN HTTP proxy or expose the unencrypted Core backend.
- Check all existing listeners before choosing ports: a wildcard stream bind
  can collide with a listener bound to a private address on the same port.

WireGuard's endpoint must also be direct/DNS-only. WSS/MASQUE remain false,
OpenVPN/IKEv2 remain false, and `NODE_EXTERNAL_TRANSPORTS` is empty. No client CA
for the deferred certificate-based transports is needed for this profile.

Render into a new private directory for review using
`deploy/host/render-quadlets.sh`; review checksums and generated units before any
separately approved installation. Expected exposure is:

- Public: the approved HTTPS web/API endpoint, the chosen WireGuard UDP port,
  and the chosen HTTPS CONNECT TCP port.
- Loopback/private only: Core HTTP, CONNECT backend, Control container HTTP,
  PostgreSQL, PgBouncer, Redis, metrics, Prometheus and Grafana.
- No MASQUE UDP bind, DCO/IKEv2 gateway units, or external-gateway health mounts.

## Inventory and client availability

Use the existing normalized `vpn_server_transports` contract. The MVP server's
advertised capabilities must be exactly `wireguard` and `proxy`, enabled only
after their applicable acceptance gates pass. Do not insert healthy observations
or certification flags to make the inventory appear ready.

Disabled/deferred capabilities must not be offered as usable connections. Keep
the existing client implementations for future nodes, but advertise only this
node's actual accepted inventory. When the sole node is unavailable, clients
must fail closed rather than claim failover or silently connect without protection.

## Required acceptance before opening the beta

1. Resolve host security support. A new container does not patch an unsupported
   host kernel; selecting fewer transports does not resolve host EOL.
2. Confirm authorized read-only access to the exact registry packages and a new
   coordinated candidate. Verify immutable version tags, signatures, digests,
   SBOM/provenance and client package checksums. Do not reuse a historical tag.
3. Complete real OIDC/PKCE, audiences, roles, callback origins, quotas, admission,
   signing/encryption secrets and private observability. No public-client secret
   may be embedded in Desktop or extension packages.
4. Demonstrate WireGuard handshake, egress, managed DNS, kill-switch, isolation
   from other clients and shared-host services, revocation, reconnect and cleanup
   using the signed installed RPM and its exact supported distribution.
5. Test the exact Firefox/Midori and Chromium packages in clean profiles: TLS,
   PKCE, scoped proxy credentials, protected navigation, DNS/WebRTC behavior,
   UUID persistence, logout/revocation, browser restart and node outage. Reject
   unauthenticated proxy use and private/link-local/metadata destinations.
6. Prove recovery of data and keys, off-host backup, alerts delivered to an
   operator, and rollback. Measure agreed concurrency/latency/throughput limits.
7. Complete privacy/terms, support/abuse procedures and distribution approvals.
   Signed packages, store submission and opening the service require their
   respective approvals; source CI does not authorize any of them.

Keep maintenance active until these gates pass. Additional transports and nodes
have their own later acceptance; deferring them is not evidence that they passed.
