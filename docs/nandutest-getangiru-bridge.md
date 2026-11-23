# Ñandutest ↔ Getangiru — integración con evidencias

## Estado real

Ñandutest sigue usando gpt-4o-mini como perfil activo. Getangiru (memoria) y Tenonderã (Qwen local en su Sprite) viven separados. La inferencia de llama.cpp está atada a 127.0.0.1:18080 del Sprite de Tenonderã; no es accesible desde Fly.io con esa dirección. El gateway privado estable entre entornos todavía no está identificado. No utilizar Quick Tunnels temporales para datos sensibles. No reutilizar secretos de Tenonderã ni OpenAI.

**Este release publica integración preparada y panel de diagnóstico, pero no dice que Getangiru o Qwen estén conectados hasta obtener evidencia de una respuesta real.**

## Memoria Getangiru: contrato y secretos

Crear un gateway HTTPS administrado, con token exclusivo de un solo tenant/espacio. El endpoint de solo lectura es GET /v1/memories/search con parámetros q, space, mode=text y limit=4. Exigir que tanto el documento como cada resultado devuelvan el mismo campo space aprobado. Si la API actual no devuelve el ámbito, extenderla mediante adaptador en Getangiru; Ñandutest la rechaza para evitar filtraciones entre proyectos.

Configurar en secretos Fly:
- GETANGIRU_READ_ENABLED=1
- GETANGIRU_BASE_URL=https://<host-estable-aprobado>
- GETANGIRU_ALLOWED_HOST=<host-exacto>
- GETANGIRU_MEMORY_SPACE=<espacio-del-piloto>
- GETANGIRU_TENANT_TOKEN=<secreto-exclusivo>
- GETANGIRU_ALLOW_PRIVATE_HTTP=1 solo para red .internal Fly privada o loopback autorizado.

La URL, credenciales y espacio se establecen del lado servidor; el navegador no puede redirigir búsquedas a otro proyecto. El piloto cubre un único espacio, no varias empresas.

## Motor local compartido

Publicar a través de un gateway privado autenticado las rutas OpenAI compatibles /v1/models y /v1/chat/completions del modelo autohospedado. Nunca exponer el puerto llama.cpp directamente a Internet. Configurar:
- NANDUTEST_SHARED_LLM_BASE_URL=https://<gateway-aprobado>/v1
- NANDUTEST_SHARED_LLM_ALLOWED_HOST=<host-exacto>
- NANDUTEST_SHARED_LLM_MODEL=<modelo-real>
- NANDUTEST_SHARED_LLM_API_KEY=<clave-propia-de-inferencia>
- NANDUTEST_SHARED_LLM_ALLOW_PRIVATE_HTTP=1 solo en red privada autorizada.

En Sistema → LLM → Getangiru, probar el modelo. La prueba usa exclusivamente el texto sintético “Responde solo LISTO”, no documentos, y exige respuesta de inferencia no vacía. Solo entonces crear y activar un perfil OpenAI compatible con URL/modelo verificados. El panel distingue conectado, probado y activo; un perfil externo no aparece como local.

El perfil GPT externo se conserva hasta habilitar una ruta local real. Como fallback, su uso para datos de negocio requiere autorización explícita.

## Límites, prioridades y memoria

- Memoria read-only: máximo 4 resultados, 180 caracteres por consulta, 64 KiB por respuesta, timeout 2,8 s, sin redirects ni proxy.
- Caché: 64 consultas durante 60 segundos, con hashes de consultas y sin texto en logs; dos búsquedas simultáneas como máximo; 20/minuto y 200/día.
- Prueba de inferencia: una petición simultánea, 20 pruebas/día, máximo 16 tokens de salida, timeout 25 s; no afecta el tráfico normal de otros servicios.
- Aprendizaje revisado: source_id y veredicto confirmado/descartado/desactualizado en PostgreSQL, filtrado de fuentes rechazadas en búsquedas futuras. No se almacenan prompts y no se reentrenan pesos.
- Métricas observables: llamadas, aciertos de caché, errores, p95, revisiones y latencia de pruebas. No inventar precisión ni ahorro de tokens.

Para reservar inferencia **entre** Getangiru, Tenonderã y Ñandutest, las tres plataformas necesitan un gateway común. Política futura: P0 incidentes interactivos; P1 análisis; P2 grafos/indexaciones de fondo; cuotas por tenant, colas, backpressure y uso medido. Este release NO afirma tener esa capacidad global todavía.

No ampliar la VM Ñandutest de 1 GiB para instalar Qwen. Si hay colas/OOM, aumentar recursos únicamente en un servidor de inferencia separado previa medición.

## Validación y reversión

Revisar HTTP 401 sin sesión para GET /api/runtime/getangiru, POST /api/runtime/getangiru/search, POST /api/runtime/getangiru/feedback y POST /api/runtime/shared-model/test. Sin secretos, el panel debe mostrar desconectado. Con infraestructura, probar memoria sintética, rechazo de espacio ajeno, feedback y generación real. El acceso delegado continúa bloqueado por defecto.

Revertir con GETANGIRU_READ_ENABLED=0 y retirando la configuración del modelo. No borrar datos ni memorias. El puente no escribe en Getangiru.


## 23/11/2026 — conexión 6PN confirmada

- Getangiru y Tenonderã tienen los servicios `fly6pn` y `fly6pn-dns` activos y DNS privado resolviendo desde la máquina Ñandutest.
- Getangiru: `GET /v1/memories/search` mediante `sprite-getangiru._peer.internal:18080` respondió HTTP 200 con `space=nandutest`, token de lectura y `items=[]` en la prueba sintética.
- Qwen: la ruta privada `sprite-tenondera-integrado._peer.internal:8080/v1/models` respondió 401 sin credencial, validando protección y conectividad. Prueba autenticada pendiente de incorporación de secretos nuevos a release.
- No activar por afirmación de despliegue; confirmar secret `NANDUTEST_SHARED_LLM_API_KEY` dentro de instancia, inferencia real desde Fly y controles RBAC. Se mantiene fallback y rollback.
