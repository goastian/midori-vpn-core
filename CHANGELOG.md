# Changelog

## 2.0.0 - 2026-08-24

### Security

- HTTP access logs now record only the method and normalized path plus response metrics. OAuth callback query parameters, client addresses, headers and request bodies are never written to the access log.
- Extension trust now distinguishes unknown, trusted and administratively revoked origins. Revoked installations are denied before an OAuth code is exchanged, and administrators can list, revoke and restore exact extension origins through protected endpoints.
- CONNECT target validation now resolves once and dials only the validated public IP answers, rejects mixed public/private DNS results and reserved ranges, and omits browsing targets, users and client addresses from proxy logs.
- Browser-extension CORS now accepts only explicitly configured or database-registered exact origins. The one first-use exception is limited to the PKCE token callback, and trusted-origin persistence now matches the deployed `created_at`/`updated_at` schema.
- Public readiness now exposes only aggregate state. PostgreSQL/Redis latency and WireGuard interface diagnostics moved behind the authenticated administrator API, and Nginx explicitly refuses public `/metrics` requests.
- Added a shared OpenVPN/IKEv2 client PKI based on device-generated ECDSA CSRs. Core signs and revokes public certificates, publishes a CRL, enforces per-account certificate limits, and never receives or stores device private keys.
- HTTPS-only CONNECT proxy contract with TLS required either directly or at the trusted host Nginx endpoint.
- Proxy authentication now accepts only short-lived `vpn-proxy` scoped credentials; general access tokens are rejected.
- WSS and MASQUE relays require short-lived `vpn-tunnel` credentials bound to the user, active peer and selected server.
- Replaced the shared Core token with Ed25519 node identities, timestamped requests, Redis-backed nonce replay protection and immediate revocation.
- Removed server-side key generation, unsigned node headers, development token bypasses and the extension's extractable PBKDF2 token-key fallback.

### Operations

- Added rootless Podman development images for Go, Control and Desktop workflows.
- Added immutable migrations through version 11, including billing/quotas, transport health, unique active peer addresses, Ed25519 identities, removal of retired transport columns, revocable per-device client certificates and the missing Mesh exit-node protocol/capability fields.
- Deployment scripts reject default credentials and publish proxy upstream only on loopback.
- Added reversible Quadlet configuration for MASQUE, Redis 8.10.1 migration with volume export, PostgreSQL 18 migration-chain tests, Certbot reload hook and Redis persistence sysctl.
- Updated CI to Go 1.27, Node 24/npm 12 and current stable action majors; Linux releases are signed RPMs built entirely with rootless Podman.
- Added a validated Quadlet helper that pins locally built images to `Pull=never`, avoiding an accidental registry pull during a controlled staging restart.
- Added explicit principal (Control plus local Core) and regional Core deployment
  profiles. Regional nodes omit the business database, Authentik, Control SPA
  and private Control/CA signing keys and accept only Ed25519-signed management.
- Added rootful system Quadlets for OpenVPN 2.7.5/DCO and strongSwan 6.0.7/XFRM
  after their kernel data planes failed in user namespaces. Both use host
  networking, minimal capabilities, read-only filesystems, private runtime
  tmpfs mounts and atomic health files; hardened host units remain fallbacks.
- Normalize Core's DER client CRL to verified PEM in both OpenVPN and strongSwan gateways before atomic activation.
- Route the public device CA and DER CRL through Nginx before the SPA fallback, and document the persistent SELinux label required for a rootless Core to read host gateway health.
- Added a hardened host OpenVPN fallback for kernels where the rootful DCO
  probe fails. Its verifier publishes fresh atomic health through the same
  read-only runtime boundary used by IKEv2.

### Mesh

- Restored authenticated creation, invitation rotation and joining of named Mesh networks, with ownership, capacity and expiry checks.
- Auto-Mesh treats Geo-IP as optional discovery metadata: trusted client-origin parsing remains strict, but an unavailable provider now creates a neutral `[Global]` session (`ZZ`) instead of blocking encrypted Mesh activation. A later activation refreshes the real country when lookup recovers.
- Added the forward-and-backward-tested migration for `proxy_scheme`, TCP and UDP capabilities in Mesh members and user exit-node selections, eliminating registration failures on upgraded databases.

### Transport contracts

- Added the normalized `vpn_server_transports` schema. Server capabilities carry enabled state, priority, health state, check timestamp and protocol metadata; the retired proxy/WSS server columns are removed after a guarded migration.
- Added validated, atomic transport configuration in the administrator API and Control panel. Operators configure WireGuard, WSS, MASQUE, OpenVPN, IKEv2 and proxy endpoints in one contract; gateway health remains `unknown` until a real probe reports it.
- Added short-lived `vpn-tunnel` credentials bound to a user, active device and server; the credential endpoint does not expose an unfinished transport.
- Added authenticated UDP↔WSS and RFC 9298 HTTP/3 CONNECT-UDP MASQUE gateways with server binding, connection limits and race-tested end-to-end relay tests.
- Smart transport selection now measures real WireGuard handshakes and falls back by health and priority across WireGuard, WSS and MASQUE.
- Health-gated capabilities prevent an enabled but unreachable gateway from being advertised. OpenVPN health now requires its private management socket, live interface and an explicit DCO initialization marker; new host deployments use a fixed, fresh status file while arbitrary paths and health URLs are rejected.
- IKEv2 health requires a live VICI daemon and the expected connection. A root-owned worker atomically refreshes a fixed status file every five seconds; Core rejects stale, unsafe or malformed state from its read-only mount, and the capability remains hidden until separately certified.
- Device-certificate enrollment validity metadata now uses the exact second precision signed into X.509, preventing native clients from rejecting a correctly issued certificate because JSON retained fractional seconds.
- Added a non-overwriting PKI bootstrap for a P-256 device CA and DNS-bound server-auth gateway certificate. The gateway never mounts the CA signing key.
- Removed inactive simulated drivers and implicit ports; OpenVPN and IKEv2 now use real native clients and cannot report a connection before completing their authenticated handshakes.
