# Ñandutest — Piloto automático de auditoría controlada (23/11/2026)

## Estado actual verificado

El producto tiene un motor de tareas y workers, un planificador de agentes personalizados y una integración privada de memoria con Getangiru. Las dos tareas existentes figuran como `done`, pero sus estados no acreditan automáticamente un ciclo completo de pentesting.

Antes del nuevo piloto, no existían reglas `allow` habilitadas en las tareas 5 y 6. La función heredada `EvaluateAssetGate` deja pasar una evaluación sin allowlist; **ese comportamiento no es suficiente para autorizar un piloto automático**. Este componente nuevo implementa una comprobación adicional que falla en modo cerrado.

Evidencia de referencia, tarea 5:
- 35 hechos registrados, uno de ellos descartado por error del ejecutor; 17 intenciones finalizadas y una pausada.
- 1 hallazgo con 0 confirmados según tabla de hallazgos.
- 213 llamadas exitosas al modelo GPT-4o-mini, 9 llamadas a Qwen local con estado error.
- Getangiru recibió consultas e ingestas; solo la memoria marcada `confirmado` por una persona es elegible como contexto confiable.

## Qué hace y qué no hace el piloto

El modo inicial `passive_https` ejecuta **solamente una petición HTTPS HEAD** al dominio exacto autorizado. No sigue redirecciones, no ejecuta scripts en la página, no utiliza credenciales ni prueba acceso, no envía payloads de explotación, no dispara fuzzing y no escanea puertos. Valida DNS público, impide destinos privados o reservados, fija la IP validada para la conexión y comprueba TLS (mínimo 1.2) sin desactivar verificación del certificado.

El motor tiene una sola comprobación concurrente, timeout de 7 segundos, frecuencia de 60 a 1440 minutos, máximo un chequeo por tarea cada 60 minutos incluso tras reautorizar, vencimiento máximo de 7 días y revocación por administrador. Los eventos registran únicamente código HTTP, resultado, latencia y cambio de estado. No se almacena cuerpo de respuesta.

### Activación administrativa

1. Registrar objetivo exacto en el alcance de la tarea.
2. Definir y habilitar una regla `allow` de tipo `exact_domain` que coincida **exactamente** con ese dominio, sin reglas de bloqueo contradictorias.
3. En la pestaña **Piloto continuo**, aportar ticket de autorización de 8 a 128 caracteres, seleccionar dominio, vencimiento e intervalo.
4. Pulsar **Autorizar comprobaciones pasivas**. Hasta ese momento, el planificador no debe realizar solicitudes externas.
5. Para una comprobación inicial, usar **Verificar ahora**. Registrar el resultado, latencia y estado del dominio. El chequeo manual también respeta el límite de frecuencia.
6. Utilizar **Revocar autorización** ante cualquier cambio de alcance o suspensión. El próximo ciclo vuelve a verificar las reglas de alcance; si se han retirado, revoca automáticamente el piloto.
7. Revisar el historial y las diferencias; abrir acciones de investigación con aprobación humana. No convertir diferencias de HTTP o respuestas LLM en vulnerabilidades confirmadas.

### API restringida a superadministradores

- `GET /api/tasks/{id}/pilot`: fases, herramientas, métricas reales y autorización.
- `POST /api/tasks/{id}/pilot/authorize`: JSON con `domain`, `ticket`, `mode: "passive_https"`, `expires_at` RFC3339 y `interval_minutes` (60–1440).
- `POST /api/tasks/{id}/pilot/check`: una comprobación de bajo impacto cuando está autorizada y venció el intervalo.
- `POST /api/tasks/{id}/pilot/revoke`: revoca el piloto.

El `requireAuth` existente deniega el acceso a visitantes no autenticados y escrituras delegadas.

## Modelo de fases basado en evidencia

1. Mandato / autorización de alcance: **bloqueado** sin ticket, expiración y allowlist.
2. Preparación técnica: instalación del navegador y de Puppeteer.
3. Reconocimiento: se puede registrar actividad previa sin asumir cobertura completa.
4. Evaluación: diferenciar hallazgos de hallazgos confirmados.
5. Validación técnica: requiere otra aprobación específica, no cubierta por HEAD.
6. Prueba de acceso: solo con cuentas de prueba y prueba específica documentada, nunca declarada por inferencia.
7. Impacto y alcance: evidencia y revisión humana.
8. Informe, remediación y reverificación: cierres verificables, sin confundir el estado `done` con todas las fases probadas.

Un pentest intrusivo **no está autorizado por la mera activación del piloto pasivo**. Explotación, post-explotación, persistencia, desplazamiento lateral, extracción de datos y cambios en producción quedan fuera de este automatismo. Requieren autorizaciones específicas, ventanas, responsables y límites operativos aparte.

## Aprendizaje continuo y límites

- Cada verificación pasiva crea un evento histórico; la vista permite comparar latencias, resultado HTTP y cambios de estado.
- Los hechos de agentes pasan a Getangiru para revisión. Solo memorias aprobadas pueden incorporarse como contexto. Esto no entrena automáticamente pesos de Qwen ni acredita exactitud.
- La calidad del LLM se muestra a partir de errores y respuestas registradas, no de supuestos. Se debe corregir la fiabilidad del Qwen local antes de desplazar completamente el motor externo.
- La API activa de Ñandutest, el navegador y la memoria privada se verifican por separado de la efectividad de cualquier auditoría externa.

## Pruebas y reversión

`go test ./... -count=1`, `go vet ./server`, verificación del frontend, test de hostname/IP privados, prueba de auto-bloqueo sin autorización y build protegido. Con la configuración actual se espera **0 chequeos externos** al desplegar porque no hay autorizaciones del piloto. No reejecutar tareas 5/6 como parte del despliegue.

Para desactivar: revocar autorización desde UI/API. Para revertir el código: rollback mediante el flujo de Fly.io/GitHub Actions, conservando las tablas históricas. No aumentar la RAM de la máquina.


## Laboratorio integral aislado para validar las ocho fases

La acción **Probar las ocho fases en laboratorio** del panel requiere
autorización explícita del superadministrador y ejecuta
\`/usr/local/lib/nandutest/pilot_lab.py --authorize-lab\`.
El script es inmutable en la imagen (propiedad root, solo lectura),
recibe un entorno sin tokens de Fly.io y levanta un servidor HTTP temporal
únicamente en \`127.0.0.1\`. La autorización de este laboratorio es
independiente de una autorización de pentesting externo.

Las fases verifican un contrato de API de ensayo, controles negativos
HTTP 401, uso de una credencial efímera de laboratorio que abre un
canario sintético, verificación del marcador y evidencia de informe.
Se guarda únicamente el hash del marcador, duración y fases completadas.
**No representa acceso real a Negofin, Crediágil ni otros entornos.**

Las tres pruebas unitarias de \`scripts/test_nandutest_pilot_lab.py\`
comprueban denegación sin autorización, recorrido de ocho fases y
unicidad de las pruebas. La construcción de Docker también ejecuta el
laboratorio como usuario \`artex\` y falla si no puede completarse.

La cobertura de producción continúa sujeta a aprobación administrativa
por objetivo exacto, y fases intrusivas permanecerán pendientes hasta
que exista una autorización y un plan de pruebas distinto del piloto pasivo.
