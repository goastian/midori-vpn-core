# strongSwan 6/IKEv2 EAP-TLS gateway

IKEv2 is implemented with the same per-device P-256 certificate issued by Core for OpenVPN. The Desktop private key is generated locally, remains in Secret Service and is materialized only in its mode-0700 runtime directory while the tunnel exists.

## Why this gateway is rootful

The gateway must use the Linux XFRM IPsec stack. A rootless Podman smoke on the
supported host fails to create `NETLINK_XFRM` even with container `NET_ADMIN`,
so a rootless strongSwan process cannot install a real CHILD_SA. strongSwan's
`kernel-libipsec` alternative uses a TUN device and user-space ESP, but its own
documentation discourages it for security gateways and high traffic. The next
required tier is a rootful Podman container with host networking and only its
network capabilities. The hardened host unit is a fallback only if the target
kernel fails the rootful XFRM probe.

Do not certify IKEv2 merely from process or VICI health: a real CHILD_SA and
traffic must still be demonstrated. References: [strongSwan cloud/container guidance](https://docs.strongswan.org/docs/latest/howtos/cloudPlatforms.html) and [kernel-libipsec limitations](https://docs.strongswan.org/docs/latest/plugins/kernel-libipsec.html).

## Rootful Quadlet

The image supplies strongSwan `6.0.7`, nftables, curl and OpenSSL. The host
supplies rootful Podman, Linux XFRM and forwarding:

```bash
podman build -f deploy/strongswan/Containerfile \
  -t localhost/midorivpn-ikev2:2.0.0 .
install -m 0600 deploy/strongswan/ikev2.env.example /etc/midorivpn/ikev2.env
install -m 0644 deploy/strongswan/ikev2-gateway.container.example \
  /etc/containers/systemd/midori-ikev2.container
systemctl daemon-reload
systemctl enable --now midori-ikev2.service
```

`midorivpn-ikev2.service.example` is the final host fallback. It must not
coexist with the rootful Quadlet.

Generate PKI once with `scripts/bootstrap-client-pki.sh`. Core receives the CA certificate and signing key. The gateway receives only `client-ca.pem`, `gateway.crt` and `gateway.key`; the CA signing key must never be copied to it.

The service validates the server-auth purpose and DNS SAN, downloads Core's DER CRL over HTTPS, converts it to PEM, verifies its CA signature, and reloads credentials every minute. It requires EAP-TLS, IKEv2, AES-GCM and PFS, and rejects password authentication and legacy cipher suites.

## Private health path for rootless Core

The health process calls VICI every five seconds and requires the
`midori-ikev2` connection to be loaded; a live PID or bound UDP socket is
insufficient. After a successful query it atomically publishes
`/run/midorivpn-health/ikev2.json`. Core rejects non-regular, writable, invalid
or older-than-15-second status files. A failed VICI query removes the file.

Bind-mount the host directory read-only into the Core container. Create it on
every boot with `systemd-tmpfiles` as root-owned mode 0755. On SELinux hosts,
register `/run/midorivpn-health(/.*)?` as `container_file_t` with
`semanage fcontext`, run `restorecon`, and mount it without a Podman relabel.
This lets the capability-limited root gateway publish status while the
rootless Core can only read it:

```ini
Volume=/run/midorivpn-health:/run/midorivpn-health:ro
```

The directory is root-owned and mode 0755. The status file is mode 0644; the
VICI socket and all private keys stay in the separate mode-0700
`/run/midorivpn-ikev2` directory.

Configure the transport with the fixed status file and keep it uncertified:

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
    "health_file": "/run/midorivpn-health/ikev2.json",
    "certified": false
  }
}
```

Core records `healthy` only when the Unix-socket probe succeeds. User clients still cannot see the capability until `certified` is explicitly changed to `true` after E2E.

## Certification gate

Initially set `IKEV2_PORT=15000` and `IKEV2_NAT_T_PORT=14500`, leaving router and firewalld rules closed. Verify service health and local XFRM state first. Before the remote E2E, restart the rootful gateway with `IKEV2_PORT=500` and `IKEV2_NAT_T_PORT=4500`, then restrict those UDP ports to the tester address.

The router must preserve the IKE ports: public `500` must reach host `500`, and public `4500` must reach host `4500`. Do not translate `500` to `15000` or `4500` to `14500`. A client contacting port 500 sends plain IKE, while strongSwan treats traffic received on a non-standard port as encapsulated and expects a four-byte Non-ESP marker; port-only translation therefore causes a silent handshake drop.

During the controlled staging window, validate:

1. EAP-TLS handshake and a real CHILD_SA with the device URN identity.
2. Full-tunnel traffic, assigned virtual IP, DNS through the configured resolver and leak prevention.
3. Kill switch on gateway loss and complete route/XFRM/interface cleanup on disconnect.
4. CRL rejection after revoking the active device certificate, followed by fresh enrollment.
5. MOBIKE/NAT-T behavior and reconnect after a network change.

If any check fails, restore `certified=false` and close the temporary rule. Only after the full matrix passes may UDP `500` and `4500` be opened normally.
