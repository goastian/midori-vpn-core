# OpenVPN 2.7/DCO gateway

This gateway is intentionally not enabled by the generic deployment. The
reference staging deployment has passed native Desktop DCO, authenticated
tunnel, traffic, DNS, kill-switch, revocation and cleanup checks. Every new
server must repeat the certification gate below before opening `1194/udp` or
setting `certified=true`.

## PKI

Generate the device CA and gateway identity on the secrets host:

```bash
GATEWAY_DNS_NAME=vpn.example.test \
PKI_DIR="$HOME/.config/midorivpn/pki" \
bash scripts/bootstrap-client-pki.sh
```

Core receives `client-ca.pem` and `client-ca.key` through the existing `VPN_CLIENT_CA_CERT` and `VPN_CLIENT_CA_KEY` file variables. The OpenVPN container mounts only `client-ca.pem`, `gateway.crt` and `gateway.key`; it never receives the CA signing key. Desktop generates every device private key locally and sends only its CSR to Core.

## Recommended rootful Quadlet

OpenVPN DCO must run in the initial host network namespace. A rootless user
namespace can load the module and create a nominal interface but cannot
reliably complete DCO peer operations. A rootful container with host networking
retains the initial network namespace without installing the VPN process or its
dependencies on the host:

```bash
podman build -f deploy/openvpn/Containerfile \
  -t localhost/midorivpn-openvpn:2.0.0 .
install -m 0600 deploy/openvpn/openvpn.env.example /etc/midorivpn/openvpn.env
install -m 0644 deploy/openvpn/openvpn-gateway.container.example \
  /etc/containers/systemd/midori-openvpn.container
systemctl daemon-reload
systemctl enable --now midori-openvpn.service
```

The host provides rootful Podman, the `ovpn` kernel module,
`net.ipv4.ip_forward=1`, and the three PKI files below `/etc/midorivpn/pki`.
The service validates the gateway hostname and certificate, downloads and
verifies the signed CRL, creates only its dedicated nftables NAT table, and
removes runtime health and firewall state on shutdown.

It publishes health atomically to `/run/midorivpn-health/openvpn.json`. Core
must mount `/run/midorivpn-health` read-only. The reader rejects links,
writable files, unknown JSON fields, invalid state, future timestamps, and
data older than 15 seconds. Keep `1194/udp` closed while staging.

## Host fallback

`midorivpn-openvpn.service.example` is retained as the last-resort host
fallback. It may be selected only after a rootful container probe fails on the
target kernel and the failure is recorded. Stop and disable the Quadlet before
starting the host unit; their `Conflicts=` contract prevents coexistence.

The server requires TLS 1.3, client certificates, CRL verification, AEAD-only
ciphers, `topology subnet` and `allow-compression no`. Its private health file
exists only while the management socket answers, the interface exists and the
OpenVPN log confirms that the DCO device opened.

## Transport contract

Keep the server transport disabled during setup. Its metadata must include:

```json
{
  "server_name": "vpn.example.test",
  "dns": ["9.9.9.9"],
  "health_file": "/run/midorivpn-health/openvpn.json",
  "certified": false
}
```

After rootful validation, enable the transport and wait for Core to record
`healthy`. It remains withheld from users while `certified` is false. For the
controlled certification window, restrict UDP 1194 to the tester address and
set `certified` to true; immediately restore `false` and close the temporary
rule if authenticated Desktop E2E, CRL rejection, DNS-leak, kill-switch or
disconnect testing fails. Publish the normal UDP rule only after the complete
matrix passes.
