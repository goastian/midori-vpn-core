# WireGuard sobre WSS: activación operativa

Este transporte está apagado por defecto. No se debe anunciar ni activar hasta
que Core, Nginx y el registro del servidor representen la misma máquina con
WireGuard escuchando localmente.

## Requisitos

1. Aplicar las migraciones hasta la versión 9.
2. El proceso de Core y el puerto WireGuard configurado por `WG_PORT` deben
   ejecutarse en el mismo host. El relay solo abre UDP hacia `127.0.0.1:WG_PORT`.
3. Nginx debe usar `core-vhost.conf.template`, incluyendo el bloque exacto
   `/api/v1/tunnel/ws`, y terminar TLS para el nombre público elegido.
4. La versión Desktop debe incluir el relay UDP↔WSS de 2.0.0.

## Configuración por servidor

Obtén el UUID del registro de `vpn_servers` que corresponde al Core local y
configúralo en su entorno:

```dotenv
WSS_TUNNEL_ENABLED=true
WSS_TUNNEL_SERVER_ID=<uuid-del-vpn_server>
WSS_TUNNEL_MAX_CLIENTS=100
```

En el API administrativo, añade un transporte normalizado `wss` con el FQDN
TLS público, puerto `443`, `enabled: true` y prioridad menor que WireGuard
directo. No existen campos WSS paralelos en `vpn_servers`. La respuesta de
`GET /api/v1/control/servers` solo lo anunciará cuando su sonda sea saludable:

```json
{ "protocol": "wss", "host": "vpn.example.org", "port": 443, "enabled": true, "health_status": "healthy" }
```

No habilites la capacidad para otro UUID: el gateway rechaza el token ligado a
un servidor distinto.

## Validación mínima

1. Sin cabecera `Authorization`, `GET /api/v1/tunnel/ws` debe devolver `401`.
2. Un token de túnel de otro servidor debe devolver `401`.
3. Un Desktop autenticado debe seleccionar **WireGuard sobre WSS** y completar
   intercambio WireGuard; comprobar bytes y handshake, no solo el estado visual.
4. Desconectar debe cerrar el relay local, eliminar el peer y restaurar el
   kill switch/DNS.

Mantener `WSS_TUNNEL_ENABLED=false` si cualquiera de esas pruebas falla.
