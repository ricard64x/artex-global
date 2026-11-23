# Ñandutest — Integridad de herramientas y prevención de ciclos de fallo

## Incidente observado: tarea 5, worker #81

El historial de la ejecución finalizada mostró 13 errores de Bash en 15 intentos, 12 errores de Write en 12 intentos y 3 errores de Edit en 14 intentos. El worker consumió 50 rondas y 14m40s, con entradas JSON truncadas y comandos incompatibles: python3 runtime_harvest.js, acceso a una carpeta api-recon/recon/ inexistente y escritura repetida sobre las plantillas compartidas.

La traza de uso de LLM demostró que OpenAI atendió turnos con máximo de salida heredado del modelo primario Qwen (256 tokens). El problema era operacional; no representa un hallazgo sobre el objetivo.

## Controles implementados

- Bash valida los comandos simples de JavaScript/Node y bloquea ejecutar un archivo .js con Python. Para runtime_harvest.js, un navegador ausente devuelve limitación operativa; no reescribe el script ni instala Chromium automáticamente.
- Write/Edit no pueden modificar /app/skills, ni por ruta normalizada ni por enlaces simbólicos existentes. Se preservan espacios de trabajo por tarea.
- Write rechaza operaciones excesivamente largas en la entrada (>16 KiB), con mensaje explicativo.
- En cada worker, cuatro errores deterministas consecutivos del mismo tipo (JSON de herramienta truncado, ruta protegida o intérprete incompatible) cancelan la sesión en curso. Los errores de red o HTTP del objetivo no activan este freno. Los resultados anteriores quedan conservados.
- Cuando Qwen autohospedado es primario y una llamada requiere herramientas, el pool usa únicamente miembros compatibles. El respaldo Cloud recibe una reserva de salida de 3072 tokens, sin modificar el límite de 256 tokens usado por el gateway local para solicitudes sin herramientas. Si no hay miembro compatible, se devuelve un error explícito sin lanzar llamadas de herramientas contra Qwen.
- Ninguno de estos cambios amplía el alcance autorizado de las pruebas de seguridad ni repite tareas finalizadas automáticamente.

## Evidencias y comprobación

- Pruebas de regresión para intérprete, protección de archivos, argumentos excesivos, comportamiento de failover y cancelación de bucles.
- Ejecutar go vet ./agent ./llmpool ./server y go test ./... -count=1.
- Validar el release de Fly.io y GET /api/health sin usar el host objetivo.
- La tarea 5 permanece finalizada; los resultados y los errores históricos no se eliminan. Una nueva ejecución del worker #81 solo debe realizarse con una solicitud y autorización separadas.

## Reversión

Revertir el commit de estos archivos en deploy/nandutest-production y ejecutar el pipeline protegido. Conservar las credenciales y el estado de Getangiru/Ñandutest sin cambios. No aumentar los recursos de la máquina.
