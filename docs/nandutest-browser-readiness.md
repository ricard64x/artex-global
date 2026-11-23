# Ñandutest: disponibilidad de Chromium para api-recon

La intención 99 de la tarea 5 registró que Chromium no existe en el
entorno. Es una dependencia local, no una vulnerabilidad del objetivo.

La imagen de Ñandutest añade Chromium de Debian Bookworm y puppeteer-core
según el package-lock.json ya incluido. Las dependencias de Node se instalan
una sola vez en build; NODE_PATH permite reutilizarlas desde los directorios
de cada tarea. No se aumentan RAM, CPU ni volumen, y no se modifican
Getangiru ni Tenonderã.

La prueba local browser_smoke.js utiliza un Chromium headless para mostrar
HTML en about:blank, sin navegar al activo examinado. La fase dinámica no
se considera ejecutada ni completa hasta comprobar realmente los flujos de
api-recon con la autorización vigente.

Comprobaciones:
- chromium --version;
- node -e require(puppeteer-core);
- node /app/skills/api-recon/scripts/browser_smoke.js como usuario artex;
- API GET /api/health y pantallas;
- registro de dependencias, continuidad, tiempos y memoria.

Riesgos: tamaño adicional de imagen y uso de RAM durante Chromium.
Evitar sesiones concurrentes; mantener parches de seguridad mediante
reconstrucción. Reversión por pipeline protegido usando imagen anterior.
No reejecutar automáticamente la intención 99.
