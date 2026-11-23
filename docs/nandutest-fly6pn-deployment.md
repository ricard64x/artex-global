# Ñandutest — despliegue privado Fly6PN (23 nov 2026)

## Cambios ya aplicados

En el Sprite `getangiru`, servicio persistente `nandutest-private-memory`:
- Socket IPv6 `[::]:18080`, solo `GET /v1/memories/search`.
- Parámetros fijados: `space=nandutest`, `mode=text`, `limit=4`; consulta máxima 180 caracteres.
- Reenvío a API existente de Getangiru `127.0.0.1:8080`, manteniendo verificación del token de solo lectura.
- Pruebas: sin token 401, token sintético autorizado 200, espacio no permitido 422, otros endpoints 404.
- La API original se mantiene con autenticación propia; no se modificó la autenticación del URL público del Sprite.

En el Sprite `tenondera-integrado`, servicio persistente `nandutest-private-qwen`:
- Socket IPv6 `[::]:8080`, `/v1/models`, `/v1/chat/completions`, `/health` con Bearer dedicado.
- Reenvío únicamente a Qwen local `127.0.0.1:18080`; alias `qwen25-1.5b-local`.
- Máximo 12 KiB por solicitud, 256 tokens por respuesta, 10 solicitudes/minuto y una inferencia a la vez.
- Pruebas iniciales en puerto anterior: 401 sin credencial, 200 modelos y 200 inferencia con respuesta no vacía. Tras mover a puerto 8080 se confirmó 401 sin credencial.
- Tenonderã existente mantiene su API `3000` y modelo local `18080`; no se abrió Sprites a modo público.

En Fly `artex-global-py`, secretos configurados:
- `GETANGIRU_BASE_URL=http://sprite-getangiru._peer.internal:18080`
- `GETANGIRU_ALLOWED_HOST=sprite-getangiru._peer.internal`
- `GETANGIRU_MEMORY_SPACE=nandutest`
- `GETANGIRU_ALLOW_PRIVATE_HTTP=1`
- `GETANGIRU_TENANT_TOKEN`: token de lectura exclusivo (valor no documentado)
- `NANDUTEST_SHARED_LLM_BASE_URL=http://sprite-tenondera-integrado._peer.internal:8080/v1`
- `NANDUTEST_SHARED_LLM_ALLOWED_HOST=sprite-tenondera-integrado._peer.internal`
- `NANDUTEST_SHARED_LLM_ALLOW_PRIVATE_HTTP=1`
- `NANDUTEST_SHARED_LLM_MODEL=qwen25-1.5b-local`
- `NANDUTEST_SHARED_LLM_API_KEY`: secreto exclusivo (valor no documentado)

**Getangiru sigue desactivado** (`GETANGIRU_READ_ENABLED` no configurado). **Qwen NO está activo** como perfil de inferencia. La configuración anticipada no prueba conectividad.

## Único bloqueo externo: unir los dos Sprites a Fly6PN

Fly.io publicó Fly6PN el 18 de noviembre de 2026. Documentación:
- https://fly.io/changelog/introducing-sprites-fly6pn-connect-your-sprite-to-your-fly/
- https://github.com/symkat/sprites-fly6pn

No hubo un token WireGuard disponible mediante las acciones autorizadas actuales. No utilizar el token de la organización con privilegios amplios como reemplazo.

En Fly.io, crear un token temporal específico de WireGuard para la organización `ricardo-rodriguez-847` (expiración 30 minutos) y configurar el **Connector Custom API** con base `https://api.fly.io`, autorización Bearer y política que permita exclusivamente los Sprites `getangiru` y `tenondera-integrado`. No copiar el token al repositorio, logs, frontend ni mensajes.

En cada Sprite, tras configurar el Connector, aplicar el instalador auditado de `symkat/sprites-fly6pn` siguiendo su README; confirmar los servicios `fly6pn` y `fly6pn-dns`, un handshake WireGuard y registros DNS `sprite-<nombre>._peer.internal`.

Desde la máquina Fly Ñandutest verificar:
```
getent hosts sprite-getangiru._peer.internal
getent hosts sprite-tenondera-integrado._peer.internal
```
Ambos devolvieron vacío antes del alta 6PN (no afirmar conexión).

## Pruebas de aceptación después del 6PN

1. Resolver ambos nombres desde Fly y comprobar conectividad TCP a los puertos 18080 y 8080.
2. Confirmar 401 sin credenciales, 200 autenticado en memoria y modelo y denegación de espacios ajenos.
3. En Ñandutest, habilitar `GETANGIRU_READ_ENABLED=1`, consultar memoria sintética desde la pantalla LLM y verificar el scope.
4. Probar inferencia sintética desde Ñandutest (no solo dentro de Tenonderã); registrar latencia p50/p95, timeout y tokens.
5. Solo después seleccionar manualmente Qwen en el perfil de inferencia.
6. Mantener fallback externo condicionado a la política, sin enviar documentos sensibles sin autorización.
7. Reversión: `GETANGIRU_READ_ENABLED=0`, volver al modelo anterior y mantener credenciales en Secret Manager.

## Limitaciones pendientes

La cuota de 10/min y concurrencia 1 del gateway son locales al consumidor; el scheduler central con prioridades P0/P1/P2 entre las tres plataformas aún no está construido. Los antiguos servicios `tenondera-memory-sync` y `getangiru-ingress` figuran fallidos y requieren migración posterior a la ruta 6PN. No usar el Quick Tunnel temporal.

La operación es **parcialmente implementada** hasta verificar conexión real desde Fly.

## Verificación adicional — 23/11/2026

- Verificación directa desde ambos Sprites de `https://api.sprites.dev/v1/gateway/list`: HTTP 200; `connections=[]`, por lo que **no existe** Connector Custom API autorizado todavía.
- En `getangiru`, `sprite org list` indica que no hay una sesión Fly CLI autenticada; tampoco se dispone de un token WireGuard dedicado mediante las herramientas conectadas.
- No se creó ningún peer WireGuard, no se alteró el modo de autenticación de las URLs y **no se activó** la conexión Getangiru/Qwen desde Ñandutest.
- La interfaz del panel Fly.io requiere una sesión de navegador autorizada que no está disponible por las herramientas de administración actuales. Completar esa autorización manualmente o mediante ChatGPT Work con navegador, sin trasladar secretos a mensajes ni repositorios.

### Checklist de autorización mínimo

1. Iniciar sesión en Fly.io, organización `ricardo-rodriguez-847`.
2. Con un CLI Fly autenticado, emitir: `fly tokens create wireguard -x30m --org ricardo-rodriguez-847`.
3. En **Sprites → Connectors → Add Connector → Custom API**, usar `https://api.fly.io` con el token temporal. Limitar el Connector a `getangiru` y `tenondera-integrado`; no autorizar todos los Sprites si la política permite selección más estrecha.
4. Confirmar que ambos Sprites ven un Connector con `base_api_url=https://api.fly.io` sin imprimir ni registrar el token.
5. Auditar o fijar versión del instalador Fly6PN y ejecutarlo en cada Sprite; comprobar el handshake y la resolución DNS desde `artex-global-py`.
6. Validar peticiones autenticadas de extremo a extremo antes de activar `GETANGIRU_READ_ENABLED=1` o seleccionar Qwen como perfil principal.

**Nota:** el sistema de GitHub Issues de `ricard64x/artex-global` está deshabilitado (HTTP 410), por lo que este runbook es el registro operativo de este bloqueo.

## Evidencia operacional posterior a instalación (23/11/2026)

| Comprobación | Resultado |
| --- | --- |
| `fly6pn` / `fly6pn-dns` en ambos Sprites | servicios en ejecución, handshake presente |
| DNS privado desde máquina Ñandutest | ambos nombres `._peer.internal` resuelven |
| Gateway Qwen sin token desde Fly | HTTP 401 (acceso protegido) |
| Qwen `/v1/models` autenticado desde Fly | HTTP 200 |
| Qwen `/v1/chat/completions` autenticado desde Fly | HTTP 200, respuesta no vacía, 34 tokens, 0.596 s observados (una muestra, no p95) |
| Getangiru búsqueda autenticada desde Fly | HTTP 200 una vez, `space=nandutest`, lista vacía |
| Getangiru estabilidad de acceso entrante | **fallida**: tres pruebas consecutivas posteriores HTTP 000 por timeout; sin prueba estable |
| Controles Ñandutest sin autenticación | HTTP 401 en rutas de Getangiru y prueba de modelo |
| Salud Ñandutest después de recuperación | HTTP 200, `version=nandutest-pilot` |

### Incidente de despliegue y corrección

El flujo protegido 45110366168 pasó CI y desplegó, pero una comprobación HTTP agotó el plazo y ejecutó un rollback incorrecto a `ghcr.io/jiwoochris/artex-global:v0.3.15-global.1`, que no era la imagen anterior de Ñandutest. Se corrigió `.github/workflows/nandutest-prod-release.yml` para reintentar rutas protegidas y prohibir ese rollback a una imagen heredada. El flujo posterior 45110948679 terminó con éxito: imagen `registry.fly.io/artex-global-py:deployment-01M83A4ATJQZ3GZFKH5K1N53C7`, release 12, salud HTTP 200 y secretos del gateway Qwen presentes en el entorno.

**Decisión de habilitación:** Getangiru permanece deshabilitado por inestabilidad del peer entrante. Qwen quedó comprobado como servicio de inferencia privado, pero no se alteró el perfil por defecto del usuario. No confundir prueba HTTP de una muestra con confiabilidad, p95 ni ahorro demostrado. La disponibilidad sostenida de Getangiru requiere diagnóstico de WireGuard/6PN y pruebas repetidas antes de activar `GETANGIRU_READ_ENABLED=1`.
