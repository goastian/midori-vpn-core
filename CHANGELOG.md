# Changelog

## 2.0.0 - 2026-08-24

### Security

- Added a shared OpenVPN/IKEv2 client PKI based on device-generated ECDSA CSRs. Core signs and revokes public certificates, publishes a CRL, enforces per-account certificate limits, and never receives or stores device private keys.
- HTTPS-only CONNECT proxy contract with TLS required either directly or at the trusted host Nginx endpoint.
- Proxy authentication now accepts only short-lived `vpn-proxy` scoped credentials; general access tokens are rejected.
- WSS and MASQUE relays require short-lived `vpn-tunnel` credentials bound to the user, active peer and selected server.
- Replaced the shared Core token with Ed25519 node identities, timestamped requests, Redis-backed nonce replay protection and immediate revocation.
- Removed server-side key generation, unsigned node headers, development token bypasses and the extension's extractable PBKDF2 token-key fallback.

### Operations

- Added rootless Podman development images for Go, Control and Desktop workflows.
- Added immutable migrations through version 10, including billing/quotas, transport health, unique active peer addresses, Ed25519 identities, removal of retired transport columns and revocable per-device client certificates.
- Deployment scripts reject default credentials and publish proxy upstream only on loopback.
- Added reversible Quadlet configuration for MASQUE, Redis 8.10.1 migration with volume export, PostgreSQL 18 migration-chain tests, Certbot reload hook and Redis persistence sysctl.
- Updated CI to Go 1.27, Node 24/npm 12 and current stable action majors; Linux releases are signed RPMs built entirely with rootless Podman.
- Added a validated Quadlet helper that pins locally built images to `Pull=never`, avoiding an accidental registry pull during a controlled staging restart.

### Mesh

- Restored authenticated creation, invitation rotation and joining of named Mesh networks, with ownership, capacity and expiry checks.
- Auto-Mesh no longer invents a country for private or loopback origins. Client IP forwarding is accepted only from `TRUSTED_PROXIES`, unavailable geolocation returns the stable `origin_country_unavailable` contract, and session meshes are never persisted with a fabricated location.

### Transport contracts

- Added the normalized `vpn_server_transports` schema. Server capabilities carry enabled state, priority, health state, check timestamp and protocol metadata; the retired proxy/WSS server columns are removed after a guarded migration.
- Added validated, atomic transport configuration in the administrator API and Control panel. Operators configure WireGuard, WSS, MASQUE, OpenVPN, IKEv2 and proxy endpoints in one contract; gateway health remains `unknown` until a real probe reports it.
- Added short-lived `vpn-tunnel` credentials bound to a user, active device and server; the credential endpoint does not expose an unfinished transport.
- Added authenticated UDP↔WSS and RFC 9298 HTTP/3 CONNECT-UDP MASQUE gateways with server binding, connection limits and race-tested end-to-end relay tests.
- Smart transport selection now measures real WireGuard handshakes and falls back by health and priority across WireGuard, WSS and MASQUE.
- Health-gated capabilities prevent an enabled but unreachable gateway from being advertised.
- Removed inactive simulated drivers and implicit ports; unsupported OpenVPN and IKEv2 selections cannot report a false connection.
