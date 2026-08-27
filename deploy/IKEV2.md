# strongSwan 6/IKEv2 EAP-TLS gateway

IKEv2 is implemented with the same per-device P-256 certificate issued by Core for OpenVPN. The Desktop private key is generated locally, remains in Secret Service and is materialized only in its mode-0700 runtime directory while the tunnel exists.

## Why this gateway is a host service

The gateway must use the Linux XFRM IPsec stack. A rootless Podman smoke on the supported host fails to create `NETLINK_XFRM` even with container `NET_ADMIN`, so a rootless strongSwan process cannot install a real CHILD_SA. strongSwan's `kernel-libipsec` alternative uses a TUN device and user-space ESP, but its own documentation discourages it for security gateways and high traffic. Therefore this one component runs as a hardened host systemd service; Core, Control, OpenVPN and the other services remain rootless containers.

Do not add an IKEv2 Containerfile or claim container health unless a real CHILD_SA and traffic have been demonstrated. References: [strongSwan cloud/container guidance](https://docs.strongswan.org/docs/latest/howtos/cloudPlatforms.html) and [kernel-libipsec limitations](https://docs.strongswan.org/docs/latest/plugins/kernel-libipsec.html).

## Prerequisites and installation layout

The staging host needs strongSwan `6.0.7`, nftables, curl and OpenSSL. Use the distribution package and verify `/usr/libexec/ipsec/charon --version` before starting.

Build the health binary with the repository's Go 1.27 Podman runner, then install the following files as root:

```text
cmd/ikev2-health                         -> /usr/local/libexec/midorivpn-ikev2-health (0755)
deploy/strongswan/entrypoint.sh          -> /usr/local/libexec/midorivpn-ikev2-entrypoint (0755)
deploy/strongswan/strongswan.conf.template -> /usr/share/midorivpn/strongswan/strongswan.conf.template (0644)
deploy/strongswan/swanctl.conf.template  -> /usr/share/midorivpn/strongswan/swanctl.conf.template (0644)
deploy/strongswan/ikev2.env.example      -> /etc/midorivpn/ikev2.env (0600)
deploy/strongswan/midorivpn-ikev2.service.example -> /etc/systemd/system/midorivpn-ikev2.service (0644)
```

Generate PKI once with `scripts/bootstrap-client-pki.sh`. Core receives the CA certificate and signing key. The gateway receives only `client-ca.pem`, `gateway.crt` and `gateway.key`; the CA signing key must never be copied to it.

The service validates the server-auth purpose and DNS SAN, downloads Core's DER CRL over HTTPS, converts it to PEM, verifies its CA signature, and reloads credentials every minute. It requires EAP-TLS, IKEv2, AES-GCM and PFS, and rejects password authentication and legacy cipher suites.

## Private health path for rootless Core

The health process serves HTTP only through `/run/midorivpn-health/ikev2.sock`. It calls VICI and requires the `midori-ikev2` connection to be loaded; a live PID or bound UDP socket is insufficient.

Bind-mount the host directory read-only into the Core container:

```ini
Volume=/run/midorivpn-health:/run/midorivpn-health:ro
```

The directory is root-owned and mode 0755. The query-only socket is mode 0666 so the remapped rootless Core UID can connect; the VICI socket and all private keys stay in the separate mode-0700 `/run/midorivpn-ikev2` directory.

Configure the transport with the fixed socket and keep it uncertified:

```json
{
  "protocol": "ikev2",
  "host": "vpn.example.test",
  "port": 500,
  "enabled": true,
  "priority": 60,
  "metadata": {
    "server_name": "vpn.example.test",
    "dns": ["10.85.0.1"],
    "health_socket": "/run/midorivpn-health/ikev2.sock",
    "certified": false
  }
}
```

Core records `healthy` only when the Unix-socket probe succeeds. User clients still cannot see the capability until `certified` is explicitly changed to `true` after E2E.

## Certification gate

Initially set `IKEV2_PORT=15000` and `IKEV2_NAT_T_PORT=14500`, leaving router and firewalld rules closed. Verify service health and local XFRM state first. During the controlled staging window, restrict the real UDP 500/4500 rules to the tester address and validate:

1. EAP-TLS handshake and a real CHILD_SA with the device URN identity.
2. Full-tunnel traffic, assigned virtual IP, DNS through the configured resolver and leak prevention.
3. Kill switch on gateway loss and complete route/XFRM/interface cleanup on disconnect.
4. CRL rejection after revoking the active device certificate, followed by fresh enrollment.
5. MOBIKE/NAT-T behavior and reconnect after a network change.

If any check fails, restore `certified=false` and close the temporary rule. Only after the full matrix passes may UDP `500` and `4500` be opened normally.
