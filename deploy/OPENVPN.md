# OpenVPN 2.7/DCO gateway

This gateway is intentionally not enabled or published by the generic deployment. Port `1194/udp` must remain closed until the gateway, device-certificate revocation and an authenticated end-to-end tunnel have all passed.

## PKI

Generate the device CA and gateway identity on the secrets host:

```bash
GATEWAY_DNS_NAME=vpn.example.test \
PKI_DIR="$HOME/.config/midorivpn/pki" \
bash scripts/bootstrap-client-pki.sh
```

Core receives `client-ca.pem` and `client-ca.key` through the existing `VPN_CLIENT_CA_CERT` and `VPN_CLIENT_CA_KEY` file variables. The OpenVPN container mounts only `client-ca.pem`, `gateway.crt` and `gateway.key`; it never receives the CA signing key. Desktop generates every device private key locally and sends only its CSR to Core.

## Build and rootless Quadlet

```bash
podman build -f deploy/openvpn/Containerfile -t localhost/midorivpn-openvpn:2.0.0 .

install -m 0600 deploy/openvpn/openvpn.env.example \
  "$HOME/.config/containers/systemd/midori-control/openvpn.env"
install -m 0644 deploy/openvpn/openvpn-gateway.container.example \
  "$HOME/.config/containers/systemd/midori-control/openvpn-gateway.container"
```

The example joins `midori-control.pod` so Core can reach the DCO-aware health endpoint at `http://127.0.0.1:9194/healthz`. The pod network namespace must be created with `--sysctl=net.ipv4.ip_forward=1`; merge the provided `midori-control.pod.dropin.example` setting into the installed pod Quadlet before recreating it. The gateway verifies this setting and fails closed instead of attempting to mutate a read-only container sysctl.

The example deliberately does not add `PublishPort=1194:1194/udp`; publication is a separate post-certification operation on the pod and host firewall.

The server requires TLS 1.3, client certificates, CRL verification, AEAD-only ciphers, `topology subnet` and `allow-compression no`. The container health check is green only when the management socket answers, the interface exists and the OpenVPN log confirms that the DCO device opened.

## Transport contract

Keep the server transport disabled during setup. Its metadata must include:

```json
{
  "server_name": "vpn.example.test",
  "dns": ["9.9.9.9"],
  "health_url": "http://127.0.0.1:9194/healthz",
  "certified": false
}
```

After local gateway validation, enable the transport and wait for Core to record `healthy`. It is still withheld from the user server contract while `certified` is false. For the controlled staging certification window, restrict UDP 1194 to the tester address and set `certified` to true; immediately restore `false` and close the temporary rule if any authenticated Desktop E2E, CRL rejection, DNS-leak, kill-switch or disconnect test fails. Retain `certified: true` and publish the normal UDP rule only after the full matrix passes.
