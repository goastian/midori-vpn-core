# Changelog

## 2.0.0 - Unreleased

### Security

- Replaced shared HMAC proxy/WSS/MASQUE credentials with canonical Ed25519
  `mvpn2` tokens carrying issuer, audience, user, persistent device, server,
  cluster, `iat`, `exp`, `jti` and rotating `kid`. Regional gateways receive
  only a dedicated public trust store and fail closed on scope mismatch; the
  legacy HMAC format is development-only behind explicit opt-in.
- Control now issues strict canonical desired-state revisions signed with
  Ed25519 under a dedicated domain. Enrolled Core nodes verify target, time,
  version, local capabilities and a contiguous anti-rollback chain before an
  atomic private last-known-good activation; nodes without valid intent fail
  closed for new peers while established tunnels remain intact.
- Core nodes now generate and atomically retain a private Ed25519 identity,
  enroll through a short-lived one-use credential whose plaintext is never
  stored by Control, and sign domain-separated node-to-Control requests with a
  timestamp, body digest and Redis-consumed nonce. Reuse, replay, expiry,
  identity collision and database-backed node revocation fail closed.
- WireGuard PSKs are now encrypted at rest with versioned
  XChaCha20-Poly1305 records bound to their table and row. Control requires a
  principal-only 32-byte data key, writes ciphertext exclusively, limits
  decryption to reconciliation and authorized exports, and migrates legacy
  plaintext through a verified, resumable backfill.
- Added persistent per-installation device identities with UUID ownership,
  explicit client types and non-unique HMAC adapter references. Raw MAC
  addresses are rejected by the API contract and never stored.
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

- Added jittered 30-second desired-state polling, persisted desired/observed
  revision reporting, runtime WireGuard endpoint selection and admission
  capacity enforced under the same lock as local bundle activation. Desired
  transport intent never creates an observed certification claim.
- Added migration 18 and the operational node enrollment/heartbeat plane.
  Control binds one unique public key to each node, preserves token audit state,
  ingests bounded observed health every 30 seconds and never treats an
  unverified transport or unevaluated Core version as eligible.
- Added the migration 17 multicluster persistence model for clusters, Core
  nodes, hashed one-use enrollment tokens, desired revisions, observed history
  and one-to-one server bindings. New nodes fail closed for placement until
  lifecycle, freshness, version, revision, capacity and certified transport
  state all agree; historical unbound servers carry an explicit temporary
  migration exception.
- Made the unified Podman runner resolve nested or sibling component checkouts,
  preserve their container workdirs and caches, and reject unrelated working
  directories before invoking a toolchain. A container-free shell test covers
  both layouts and aggregate audit paths.
- Consolidated that layout resolver with the four-repository release manifest.
  Nested and sibling checkouts now produce the same canonical evidence, while
  missing repositories, mixed branch states, version drift and dirty trees
  remain fail-closed.
- Removed the one-time pre-Ed25519 environment migration, which could overwrite
  the current OAuth redirect set and depended on a mutable remote builder. The
  debt gate now rejects any return of the retired shared Core token contract.
- Removed the abandoned Tauri/Rust and non-Linux Desktop targets, their
  toolchain runner and audit exceptions. The Linux RPM now consumes its icons
  and PolicyKit files exclusively from neutral packaging paths.
- Defined the central Control and independent regional Core architecture,
  including trust and secret boundaries, signed desired-state requirements,
  failure isolation, observability, rollout/rollback and the regional
  production acceptance gate. The document distinguishes deployed behavior
  from cluster lifecycle, heartbeat and fleet-revocation work that remains.
- Added approval-gated OCI publication workflows that require the annotated
  2.0.0 tag, protected environments and explicit confirmation, then create and
  verify GitHub attestations and a keyless Cosign signature by digest.
- Added a non-publishing release evidence gate with immutable GitHub Actions,
  a four-repository commit manifest, reproducible OCI inputs, SPDX output and
  checksums. Registry upload and signing remain a separately approved stage.
- Defined the 2.0.0 release supply-chain contract for OCI images, the Linux
  RPM and browser-store packages, including immutable build inputs, SPDX SBOMs,
  provenance, existing RPM trust, keyless OCI identity and store-signing gates.
- Added private, digest-pinned Prometheus 3.14 and Grafana 13.2 Quadlets with
  loopback-only administration, a dedicated in-network scrape path, seven
  operational alerts and rollback-protected deployment. The dashboard now
  covers HTTP and provisioning percentiles, database state, transport health,
  peer capacity and aggregate traffic without user, address or destination
  labels.
- Added a pinned PgBouncer 1.25.2 rootless image and wired principal script and Quadlet deployments through transaction pooling with SCRAM-SHA-256, a read-only container, runtime-only credentials and a health-gated Core dependency.
- Replaced the legacy backup and chaos helpers with fail-fast, environment-neutral staging tests. Backup validation restores into an isolated database and compares critical tables; network chaos applies bounded netem loss, verifies private metrics and probes, and always restores the original qdisc.
- Pinned the Core builder, Alpine runtime and rootless analysis tools to exact supported versions and image digests. Staticcheck and govulncheck no longer resolve mutable `latest` releases during a rebuild.
- Added rootless Podman development images for Go, Control and Desktop workflows.
- Added immutable migrations through version 18, including billing/quotas, transport health, unique active peer addresses, Ed25519 identities, removal of retired transport columns, revocable per-device client certificates, persistent device identity, durable peer operations, safe administrative draining, encrypted PSKs, the multicluster state model, enrolled Core-node identities and the missing Mesh exit-node protocol/capability fields.
- Added migrations 13–14 and a durable PostgreSQL lifecycle for WireGuard connect
  and replacement operations. Quota and capacity are revalidated under locks,
  retries reuse the exact completed session, ambiguous failures remain
  recoverable, and the exact previous Core owner is captured before replacement
  so cleanup cannot target a later operation, including for legacy peers.
- Added fail-closed peer reconciliation at startup and every 60 seconds. It
  recovers stalled idempotent operations, keeps replacements durable until
  exact prior-owner cleanup succeeds, repairs missing sessions and counters in
  one transaction, removes observed orphans conditionally and exports bounded
  divergence, cleanup, pending-operation and observation-error metrics.
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

### API contract

- Made Core WireGuard provisioning idempotent through mandatory operation UUIDs,
  durable node-local ownership, conditional removal and explicit conflict or
  unavailable-state responses. Peer keys and PSKs now require canonical 32-byte
  base64, keepalive is bounded, and address pools preserve their configured
  prefix while rejecting ranges larger than 65,536 addresses.
- Added user device list, alias, revocation and paginated session-history
  endpoints. The primary connection list now returns active sessions only;
  revocation preserves audit history, invalidates recoverable material and
  fails explicitly when Core cleanup has not converged.
- Connection and certificate enrollment now accept a structured device
  identity while retaining deprecated `device_name` compatibility. Connection
  responses, peers and certificates expose `device_id`; quotas count devices
  with active sessions and no longer infer client type from names.
- Added a versioned OpenAPI 3.1 contract and a bidirectional router coverage
  test so method or path drift fails the Go test suite.
- Standardized JSON failures with stable machine-readable codes, including JWT,
  WSS and OAuth provider failures. Arbitrary Authentik error bodies and request
  identifiers are no longer forwarded to clients or written to application
  logs.
- Made `/api/v1/control/mesh` the exact canonical list/create path and changed
  exit-node deregistration to identify the mesh in the URL instead of requiring
  a body on `DELETE`.
- Removed the permanently unimplemented Apple mobileconfig route. Native IKEv2
  remains available through per-device certificate enrollment and the Desktop
  client, without publishing a plausible but unusable profile.
- Connection listings can no longer serialize WireGuard preshared keys.
  Authorized one-time configuration, text and QR responses are explicitly
  marked sensitive and sent with `Cache-Control: no-store`.
- Control, Desktop and browser-extension consumers now preserve stable API
  error codes instead of reducing failures to prose. Their connection-list
  types also match the secret-free OpenAPI summary contract.

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
