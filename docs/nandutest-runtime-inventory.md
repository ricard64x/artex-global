# Estado de IA e inventario de seguridad — Ñandutest

## Pantallas

- **Sistema → LLM:** muestra el proveedor, modelo seleccionado y el origen del endpoint. El nuevo panel verifica si un servicio Ollama local en puerto 11434 responde y si enumera el modelo solicitado. Solo el botón **Probar inferencia local** realiza una finalización real usando la configuración activa. No representa automáticamente la mera configuración como inferencia exitosa.
- **Sistema → Inventario de seguridad:** inventario de comandos detectados mediante una lista fija de nombres y `exec.LookPath`. Incluye estado instalada / no instalada, función y clasificación, sin ejecutar comandos ni escanear objetivos.
- **Sistema → Herramientas:** mantiene la gestión de herramientas de agentes; no confundir con binarios del sistema.

## Herramientas

En la imagen de producción actual ya existen Nmap, dig, whois, OpenSSL, curl, wget, jq, Git, Python, Node y Playwright CLI (verificados en Fly.io). La nueva imagen añade Nikto, WhatWeb, SSLScan, Gobuster y FFUF de repositorios Debian Bookworm. Nikto proviene de la sección non-free; el Dockerfile habilita únicamente la sección Debian que se necesita para instalarlo. La disponibilidad final se verificará después de desplegar, no antes.

Semgrep y Trivy siguen previstos como contenedores **aislados de ejecución temporal** para análisis de código; no se instalan en la VM de 1 GB. Nuclei sigue pendiente de una evaluación de recursos y controles de alcance.

La instalación de binarios NO los conecta automáticamente a los agentes. Requieren aprobación explícita del alcance, límites de concurrencia, registro de comandos y un entorno de ejecución separado para pruebas activas. La interfaz no incorpora un instalador remoto sin controles.

## LLM

No ejecutar Qwen3 4B en el mismo contenedor Fly.io: 1 vCPU compartida / 1 GB RAM. La futura conexión debe usar Ollama en una máquina separada sobre red privada, protegido con autenticación/acceso de red restringido. Un perfil OpenAI-compatible puede usar la URL interna del servicio, pero hasta que se verifique una finalización real debe mostrarse como **sin verificar**.

## Validaciones de aceptación

- [ ] Compilación Go, tests y Biome.
- [ ] Imagen Docker construida con Nikto, WhatWeb, SSLScan, Gobuster, FFUF.
- [ ] Prueba en Fly.io: `/api/runtime/inventory` no autenticado debe devolver 401.
- [ ] Prueba autenticada del inventario: coincidencia con ejecutables reales.
- [ ] Prueba del panel LLM: sin perfil o sin servicio debe quedar sin verificar, nunca mostrar verde.
- [ ] Confirmar que no se ejecutan herramientas activas desde el inventario.

La expansión posterior del catálogo puede incluir motores de SAST/SCA/DAST **en workers efímeros**, siempre con reportes reproducibles y métricas de costo, tiempo y falsos positivos.
