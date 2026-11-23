# Transporte privado de Ñandutest a Getangiru (preparado, no activado)

## Estado comprobado (2026-11-22)

- Getangiru en Sprite `getangiru`: búsqueda `mode=text` ahora devuelve `space` en el sobre y cada ítem. Validación de separación por tenant/space, token alternativo independiente, cuotas y worker: OK.
- Qwen en Sprite `tenondera-integrado`: `/v1/models` autenticado respondió 200 y `/v1/chat/completions` respondió 200 con salida no vacía. Modelo real `qwen25-1.5b-local`.
- Ambos Sprite URL permanecen en modo **sprite**, con autenticación de organización. No cambiarlos a `public`.
- Fly `artex-global-py`: sin secretos de conexión a Getangiru/Qwen. Ninguna integración de extremo a extremo ha sido certificada.

## Doble autenticación de Getangiru

La autenticación en la entrada del Sprite exige una credencial de organización para `Authorization: Bearer <sprite-edge-token>`, mientras Getangiru exige **otro** token exclusivamente de tenant, enviado como `X-Getangiru-Tenant-Token`. Esta rama añade soporte opcional a esa separación. Si no hay `GETANGIRU_SPRITE_EDGE_TOKEN`, se usa el comportamiento anterior.

Variables de Fly, sólo después de crear credenciales reales:

- `GETANGIRU_READ_ENABLED=1`
- `GETANGIRU_BASE_URL=https://getangiru-b5obn.sprites.app`
- `GETANGIRU_ALLOWED_HOST=getangiru-b5obn.sprites.app`
- `GETANGIRU_MEMORY_SPACE=nandutest` (debe estar autorizado dentro del tenant)
- `GETANGIRU_SPRITE_EDGE_TOKEN` = credencial **de alcance mínimo** para acceder a este Sprite, no token de administración reutilizado
- `GETANGIRU_TENANT_TOKEN` = nueva credencial exclusiva del tenant Ñandutest

**Bloqueador:** la conexión actual de Fly/Sprites no expone una acción para emitir un token de entrada a Sprite limitado exclusivamente a esa API. No copiar credenciales de otros servicios ni desactivar `url-auth sprite`. Revisar capacidades de tokens con el proveedor antes de activarlo. Una credencial de organización amplia no es equivalente a una credencial de servicio de mínimos privilegios.

## Qwen

Mantener `llama-server` en `127.0.0.1:18080`. Falta gateway de inferencia con:

- ruta OpenAI compatible `/v1/models` y `/v1/chat/completions`
- credencial separada por consumidor, traducción segura al token local y sin revelar secretos
- doble autenticación en el borde, cuota global P0/P1/P2, cancelación, cola acotada y métricas
- acceso autorizado sólo por servicio, sin desviar el puerto de la aplicación actual de Tenonderã

No usar el perfil local de Ñandutest hasta recibir 200 con respuesta real **desde Fly**, no sólo desde el Sprite.

## Evidencia mínima para cierre

1. GET de memoria autorizado desde Fly con `space=nandutest`.
2. La misma consulta con `space` ajeno devuelve vacío o denegación.
3. Token revocado o ausente produce 401/403 en el borde y en la aplicación.
4. POST de inferencia desde Fly devuelve respuesta no vacía y contabiliza tokens.
5. Confirmar cuotas y p95 en ventanas reales; registrar el resultado sin datos sensibles.
6. Mantener fallback externo sujeto a política y rollback instantáneo.

La integración sigue **desconectada** hasta cumplir esos seis puntos.
