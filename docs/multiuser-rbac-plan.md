# Propuesta de ampliación: multiusuario y control de acceso (RBAC)

**Estado:** especificación; **no implementado**.

## Situación verificada
La versión publicada de ARTEX Global contempla una sola cuenta administrativa `ARTEX` y no proporciona alta de usuarios individuales por interfaz. El servicio desplegado en Fly.io utiliza `ghcr.io/jiwoochris/artex-global:v0.3.15-global.1`, una imagen upstream precompilada: modificar archivos fuente del fork sin construir y desplegar una nueva imagen **no modifica la aplicación en producción**.

## Funcionalidad objetivo
- **Sistema → Usuarios**: alta, consulta, modificación, baja lógica, restablecer contraseña y desactivar sesiones.
- Cuentas individuales con identificador, nombre, email único, rol (y estado).
- Roles:
  - **Administrador**: puede gestionar usuarios, configuración, proveedores LLM y reglas de acceso.
  - **Operador**: puede crear y operar tareas *solo* para objetivos previamente autorizados.
  - **Auditor**: lectura de activos, ejecuciones, resultados e informes; nunca ejecuta herramientas.
- Política de roles aplicada en cada API; prohibir por defecto acciones no autorizadas.
- Hash de contraseña seguro, tasa limitada de intentos, revocación de sesiones, comprobación de autorización e identificación de cada usuario en logs.
- Considerar MFA y SSO/OIDC corporativo antes de exponer cuentas a Internet.
- Auditoría persistente: usuario, acción, fecha, origen, cambios de configuración y ejecución de herramientas.

## Arquitectura y migración
1. Inspeccionar la implementación actual de autenticación y las tablas existentes de PostgreSQL.
2. Diseñar esquema para `users`, sesiones/revocación, asignación de roles y `audit_events` (nombres finales tras revisión del código).
3. Migrar la cuenta `ARTEX` a un administrador sin invalidar arbitrariamente sesiones ni perder datos. No borrar el volumen.
4. Incorporar endpoints de administración protegidos con comprobación de permisos en backend.
5. Crear interfaz de administración de usuarios; no depender de ocultar botones como única medida.
6. Asociar ejecuciones de seguridad con usuario solicitante y ámbito autorizado.
7. Probar login, revocación, segregación de funciones, IDOR, control de acceso por rol y migraciones; primero en staging.
8. Generar una imagen propia del fork y desplegarla mediante Fly.io, reemplazando el pin upstream solo tras verificarla.

## Criterios de aceptación
- Se pueden crear usuarios separados sin compartir la contraseña administrativa.
- El perfil Auditor no puede lanzar escaneos ni cambiar credenciales.
- El perfil Operador no puede administrar usuarios y no puede ejecutar pruebas fuera del alcance autorizado.
- Se mantiene la base de datos y el volumen actuales.
- La cuenta administrativa anterior funciona tras la migración.
- Eventos sensibles quedan asociados a una identidad específica.

**Pendiente de desarrollo y pruebas. No se han creado cuentas reales.**
