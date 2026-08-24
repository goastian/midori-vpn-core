# WireGuard sobre MASQUE: operación

Core y el agente implementan HTTP/3 CONNECT-UDP conforme a RFC 9298 mediante
`quic-go/masque-go`. MASQUE no es un proxy UDP general: el gateway solo acepta
el destino local exacto `127.0.0.1:WG_PORT` y exige un token `vpn-tunnel`
ligado al peer activo y al UUID del servidor.

## Configuración de Core

```dotenv
MASQUE_ENABLED=true
MASQUE_PORT=443
MASQUE_TLS_CERT=/etc/letsencrypt/live/vpn.example.org/fullchain.pem
MASQUE_TLS_KEY=/etc/letsencrypt/live/vpn.example.org/privkey.pem
MASQUE_URI_TEMPLATE=https://vpn.example.org/masque{?target_host,target_port}
MASQUE_SERVER_ID=<uuid-del-vpn_server>
MASQUE_MAX_CLIENTS=100
```

Los directorios `live` y `archive` de Let's Encrypt se montan de solo lectura.
El usuario rootless necesita únicamente lectura/travesía sobre el certificado
seleccionado. Instala `scripts/reload-masque-certificate.sh` como hook `deploy`
de Certbot para reiniciar `control-api.service` después de una renovación. El
hook requiere `MIDORI_CERT_LINEAGE` con la ruta exacta de la línea de
certificado; no contiene un dominio por defecto.

## Puerto privilegiado con Podman rootless

No se reduce `net.ipv4.ip_unprivileged_port_start`. El pod publica
`8443:443/udp` y firewalld aplica:

```bash
sudo firewall-cmd --zone=public \
  --add-forward-port=port=443:proto=udp:toport=8443 --permanent
sudo firewall-cmd --reload
```

El router reenvía `443/udp` hacia el host. `8443/udp` no se abre ni se
reenvía en el router; es un salto interno del host.

## Contrato de transporte

```json
{
  "protocol": "masque",
  "host": "vpn.example.org",
  "port": 443,
  "enabled": true,
  "priority": 80,
  "metadata": {
    "uri_template": "https://vpn.example.org/masque{?target_host,target_port}",
    "target": "127.0.0.1:51820"
  }
}
```

La plantilla debe contener `target_host` y `target_port`; el agente rechaza
metadata incompleta o un destino que no coincida con el puerto WireGuard del
servidor.

## Validación

1. Core registra `MASQUE gateway listening port=443`.
2. `443/udp` público alcanza el gateway HTTP/3 y una solicitud sin token recibe
   `401`; la sonda marca el transporte `healthy`.
3. El agente obtiene un token ligado al peer, crea el relay UDP local y completa
   un handshake WireGuard. El estado visual por sí solo no es evidencia.
4. Al desconectar se cierran QUIC, UDP local, WireGuard, DNS y kill switch.

Las pruebas de Core incluyen un gateway TLS/HTTP3 real contra un eco UDP local;
las del agente validan ciclo de vida y rechazo de contratos inválidos bajo el
detector de carreras.
