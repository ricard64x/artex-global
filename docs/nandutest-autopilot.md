# Autopiloto: evidencia y aprendizaje del piloto por tarea

## Activación y operación

La única fuente de autorización y programación es **Revisión → Activar piloto automático** (también disponible en la pestaña **Piloto automático**). Se conservan el dominio exacto en el alcance, la regla `allow/exact_domain`, los bloqueos globales, el ticket, la frecuencia de 60 a 1440 minutos y el vencimiento máximo de siete días. El tablero **Sistema → Autopiloto de auditoría** muestra estas autorizaciones y permite consultar la evidencia, verificar cuando vence el intervalo y revocar. El botón de la cabecera abre el formulario al inicio de la revisión. Elegir dominio, intervalo, vencimiento y referencia de autorización; confirmar con **Activar piloto automático**. Si falta el alcance o el permiso, los accesos **Configurar alcance** y **Revisar permisos** llevan a su configuración. El estado y la próxima comprobación permanecen visibles en la cabecera. **Gestionar piloto automático** permite renovar la autorización o **Detener piloto**. La actualización de estado se comparte con la pestaña y se consulta cada 30 segundos mientras la página está visible; no se necesita mantenerla abierta para que el servidor programe las comprobaciones.

Este cambio amplía el análisis de **la misma petición HTTPS HEAD** del piloto. No crea un segundo planificador, no envía GET adicionales, no autoriza objetivos ni reanuda tareas existentes. Se comprueba de nuevo la autorización y el alcance antes de DNS y antes de HTTP. Una autorización renovada no habilita una ejecución anterior. La revocación cancela la petición local en curso; una solicitud ya recibida por el servidor remoto no puede deshacerse.

## Controles nativos

| Control | Evidencia | Límite de interpretación |
|---|---|---|
| DNS | Cantidad de direcciones públicas verificadas y conexión fijada a una IP | No enumera subdominios |
| TLS | Cadena/nombre verificados, versión negociada y días hasta vencimiento | No enumera protocolos o cifrados soportados |
| HTTP | Código de estado y presencia de HSTS; CSP, nosniff y Referrer-Policy cuando HEAD anuncia HTML 2xx | Presencia no demuestra eficacia de una política; HEAD puede diferir de GET |
| Cookies | Conteos de atributos Secure, HttpOnly y SameSite de cookies retornadas por HEAD | No observa cookies que solo se emiten en login o GET; la finalidad requiere revisión |

Los controles no tienen llamadas LLM y no aceptan comandos, rutas, plantillas o payloads generados por modelos. No guardan cuerpos, valores ni nombres de cookies. Son comprobaciones de configuración/disponibilidad y no equivalen a explotación, cobertura total o acceso demostrado.

## Ejecución y recuperación

Una restricción única en PostgreSQL permite una sola comprobación pasiva simultánea, incluso con varios procesos. La ejecución y su próxima fecha se registran antes de enviar tráfico; la reautorización no reinicia el límite mínimo de una hora. El planificador existente sigue consultando cada tres minutos.

Se mantiene el presupuesto de red de siete segundos, acotado además por el vencimiento del permiso. Las cabeceras se limitan a 32 KiB. Solo HTTPS público en puerto 443, sin redirecciones, proxy o credenciales. Se bloquean IP internas, reservadas, loopback, redes de traducción IPv6 y respuestas DNS mixtas público/privado. La conexión conserva la verificación TLS del nombre original.

Los fallos de DNS, TLS, red, HTTP 429 o 5xx generan espera exponencial hasta siete días y pausa al quinto fallo consecutivo. Un bloqueo de red o la retirada del alcance deshabilita la autorización. El vencimiento sigue siendo obligatorio durante las esperas. Una ejecución abandonada se marca `interrupted` al intentar una nueva admisión, tras dos minutos; no se reproduce inmediatamente. Ninguna recuperación amplía permisos o alcance.

## Evidencia y aprendizaje operativo

Cada ejecución guarda estado, duración, intentos HTTPS y observaciones sanitizadas. Un intento cuenta aunque falle conexión o TLS antes de obtener respuesta; DNS fallido antes de crear la solicitud registra cero intentos HTTPS. Se conservan las últimas 200 ejecuciones por tarea; la pantalla muestra las últimas 20. Las métricas son del historial retenido.

La comparación usa la última ejecución completa con igual origen y versión de reglas. Un control se marca resuelto únicamente con una observación positiva. Errores, controles no evaluados, cambios de origen y cambios de versión no prueban resolución.

El administrador confirma, descarta o reabre observaciones. La revisión se reutiliza dentro de la misma tarea, origen, versión y resultado de regla. Todos los controles siguen ejecutándose. Las revisiones expiran cuando su evidencia sale de la retención. Este aprendizaje clasifica resultados repetidos; no cambia pesos del modelo, no aprueba hechos Getangiru ni comparte revisiones entre tareas/objetivos. `confirmadas / revisadas` cuenta reglas revisadas, no mide precisión global de un pentest.

La descarga JSON conserva los bytes serializados por PostgreSQL. Se verifica su SHA-256 antes de entregarlos y se puede comprobar con `sha256sum`. No es una firma digital ni protege contra un administrador de BD que altere simultáneamente evidencia y hash. Los veredictos humanos son metadatos separados de la evidencia original.

## API y reversión

- `GET /api/runtime/autopilot?plan_id=<id-de-tarea>`: autorizaciones existentes, historial y métricas.
- `POST /api/runtime/autopilot/reviews`: `run_id`, `fingerprint`, `verdict`.
- `GET /api/runtime/autopilot/runs/{id}/evidence`: JSON original y SHA-256 verificado.
- Autorización, verificación y revocación conservan las rutas `/api/tasks/{id}/pilot/*`.

Todas las rutas son exclusivas del administrador. `NANDUTEST_AUTOPILOT_DISABLED=1` detiene programación y nuevas solicitudes cuando se aplica al proceso, conservando autorizaciones e historia. Para mantener la revocación incluso al volver a una imagen anterior, revocar desde el piloto por tarea antes del rollback. La migración agrega tablas de evidencia/revisión y el contador de fallos; no modifica los hechos Getangiru ni los hallazgos de tareas.

## Validación

Las pruebas unitarias simulan DNS/HTTP sin tocar objetivos externos. Comprueban alcance, DNS mixto, revocación entre pasos, ausencia de secretos/cuerpos, redirecciones, pinning, espera progresiva y comparación. `TestAuditLifecycleDB` usa PostgreSQL efímero y verifica autenticación, exclusión global, revocación, frecuencia tras reautorizar, separación de revisiones, evidencia, retirada de alcance, vencimiento y pausa tras cinco fallos. El release exige Go build/vet/tests, pruebas con PostgreSQL y exportación estática web; verifica HTTP 401 en las rutas nuevas tras desplegar.
