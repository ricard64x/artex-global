# Ñandutest — piloto de LLM local, análisis de código y administración de usuarios

**Estado:** rama experimental, no desplegada a producción. Los archivos de despliegue no instalan automáticamente los modelos ni las imágenes de análisis; deben descargarse en un host privado preparado.

## Alcance implementado
- Go + PostgreSQL: tabla `ndt_users`, auditoría `ndt_user_audit`; cuenta reservada `ARTEX` conserva el control privilegiado.
- Interfaz **Sistema → Usuarios**: alta, listado, cambio de rol, desactivación/reactivación, restablecimiento de clave y revocación de sesiones.
- Inicio de sesión individual; hash bcrypt; JWT con versión revocable; permisos obligatorios en API.
- El **operador** y el **auditor** están temporalmente limitados a endpoints de consulta expresamente autorizados. **Ningún usuario delegado puede iniciar análisis activos** ni acceder a configuración/credenciales hasta desarrollar permisos por objetivo y tarea.
- Compose `docker-compose.local-llm.yml`: Ollama separado con `qwen3:4b`, privado dentro de red Docker; endpoint compatible con OpenAI.
- `scripts/nandutest-pilot.sh`: comprobaciones estáticas sin red mediante Semgrep y Trivy, generación automática de archivos JSON y métricas básicas.

## Requisitos de infraestructura
La app actual `artex-global-py` (Fly.io, 1 vCPU y 1 GB RAM) **no ejecuta un LLM 4B**. No aumentarle recursos ni desplegar el LLM sobre esa máquina. Para comenzar, usar un **host aislado** con aproximadamente 8 GB RAM disponibles (12–16 GB recomendables para el sistema operativo y otros servicios), 2–4 vCPU, almacenamiento local y sin publicación pública del puerto 11434. El `mem_limit: 6g` es un límite configurable, no consumo medido ni garantía de performance.

## Descarga y arranque en infraestructura privada
Desde la raíz del fork, con Docker + Compose instalados. `Dockerfile.nandutest` construye el binario y la interfaz **desde este fork** (no desde upstream). El proceso se ejecuta como usuario no privilegiado UID 10001. Preparar el directorio de datos local con permisos para ese usuario (sin cambiar permisos del volumen productivo):
```bash
mkdir -p data
sudo chown -R 10001:10001 data
```
Después:
```bash
docker compose -f docker-compose.yml -f docker-compose.local-llm.yml up -d postgres ollama
docker compose -f docker-compose.yml -f docker-compose.local-llm.yml exec ollama ollama pull qwen3:4b
docker compose -f docker-compose.yml -f docker-compose.local-llm.yml exec ollama ollama list
docker compose -f docker-compose.yml -f docker-compose.local-llm.yml up -d artex
```
Definir **antes de arrancar** `POSTGRES_PASSWORD` y valores de autenticación bootstrap con los mecanismos ya existentes de Artex; no almacenar claves en git. El placeholder `OPENAI_API_KEY=local-only-ollama` es local y **no** una API key de nube. La conexión es `http://ollama:11434/v1` solo desde la red interna.

**Importante:** Artex prioriza perfiles LLM guardados en PostgreSQL sobre variables de entorno. Si ya existe un perfil guardado, el administrador deberá crear o activar en *Sistema → LLM* un perfil de formato **OpenAI**, modelo **qwen3:4b**, URL **http://ollama:11434/v1** (no exponer URL al navegador) y clave local sin secretos de terceros. Confirmar respuesta de prueba antes de iniciar agentes. No confundir el perfil de desarrollo con un endpoint público.

## Descargar herramientas defensivas e iniciar análisis local
```bash
docker pull semgrep/semgrep:latest
docker pull aquasec/trivy:latest
mkdir -p data/trivy-cache
docker run --rm -v "$PWD/data/trivy-cache:/root/.cache/trivy" aquasec/trivy:latest image --download-db-only
export NANDUTEST_APPROVED_ROOT="/ruta/raiz/de/proyectos-autorizados"
bash scripts/nandutest-pilot.sh "/ruta/raiz/de/proyectos-autorizados/repositorio"
```
El script monta el código **solo lectura**, usa `--network none`, rechaza objetivos externos al directorio autorizado y produce:
- `data/pilot-reports/<fecha>/semgrep.json`
- `data/pilot-reports/<fecha>/trivy.json`
- `data/pilot-reports/<fecha>/metrics.json`

Estas salidas constituyen el **piloto inicial de auditoría estática automatizada**, no escaneo web autónomo ni pruebas de explotación. La carga de estos reportes a los hallazgos de Artex y la orquestación desde su interfaz requieren una integración adicional.

## Medición verificable
Repetir el mismo conjunto de proyectos y conjunto de pruebas con la misma versión de reglas/herramientas. Registrar: duración p50/p95, uso pico de RAM, CPU pico/medio, porcentaje de trabajos completos, precisión (VP/(VP+FP)) tras revisión, tasa de falsos positivos, hallazgos únicos confirmados, horas de analista y costo total. No reportar mejora porcentual hasta tener una línea de base.

## Criterios obligatorios antes de ponerlo en producción
1. Ejecutar y aprobar Go build/tests y Next.js build/lint; probar migración con backup/restauración.
2. Pruebas E2E de login multiusuario, expiración/revocación, RBAC, IDOR y acceso a rutas GET con datos sensibles.
3. Verificar seguridad del contenedor: autenticación admin, aislamiento de red, protección de volúmenes y secretos; evitar usar `latest` en producción, fijar digests auditados.
4. Añadir control de objetivos y autorización documentada por usuario, cuota, pausa/cancelación, evidencia, aprobación para pruebas activas.
5. Construir y validar la **imagen propia del fork** mediante `Dockerfile.nandutest`; `fly.toml` todavía usa el binario upstream y **no despliega estos cambios**.
6. Mantener la app Fly y volumen existentes sin alteraciones hasta que el piloto esté validado.
