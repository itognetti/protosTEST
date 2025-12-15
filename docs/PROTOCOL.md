# Protocolos implementados

## SOCKS5

El servidor implementa el handshake estándar de SOCKS5 con soporte para autenticación de usuario/contraseña (método 0x02) y el comando CONNECT:

1. **Greeting**: el cliente envía `VER | NMETHODS | METHODS`. El servidor responde con `0x05 0x02` cuando la autenticación es obligatoria y con `0x05 0x00` si se permite acceso sin credenciales.
2. **Autenticación (RFC 1929)**: el cliente envía `VER | ULEN | UNAME | PLEN | PASS`. El servidor responde `0x01 0x00` en caso de éxito o `0x01 0x01` en caso de error.
3. **Request CONNECT**: el cliente envía `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT`. Se aceptan direcciones IPv4, dominios e IPv6. La resolución de nombres se realiza con timeout configurable (10s) para evitar bloqueos. El servidor responde con un paquete `VER=0x05, REP=0x00` cuando la conexión se establece.
4. **Relay de datos**: el tráfico se reenvía de manera no bloqueante y contabilizando bytes para las métricas. Si los disectores están habilitados y el destino es POP3 (puerto 110), los payloads se envían al sniffer y se registran en `pop3_credentials.log`.

## Protocolo de gestión

La API de gestión se sirve por TCP y usa estructuras binarias fijas definidas en `shared.h` (`mgmt_message_t` y respuestas específicas por comando). Un cliente debe enviar un `mgmt_message_t` completo y recibirá la estructura de respuesta asociada al comando:

- `CMD_ADD_USER` / `CMD_DEL_USER`: envían/reciben `mgmt_simple_response_t`.
- `CMD_LIST_USERS`: recibe `mgmt_users_response_t`.
- `CMD_STATS`: recibe `mgmt_stats_response_t`.
- `CMD_SET_TIMEOUT`, `CMD_SET_BUFFER`, `CMD_SET_MAX_CLIENTS`, `CMD_ENABLE_DISSECTORS`, `CMD_DISABLE_DISSECTORS`, `CMD_RELOAD_CONFIG`, `CMD_GET_CONFIG`: consumen o devuelven las estructuras homónimas.

Cada conexión de gestión se maneja en un hilo independiente para evitar bloquear el bucle principal del servidor. El socket de datos trabaja en modo bloqueante durante el intercambio para simplificar el envío/recepción completo de las estructuras.
