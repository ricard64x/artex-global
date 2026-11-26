# Autorización persistente de pentest

La autorización de pentest se guarda independientemente de la programación de
comprobaciones pasivas. Cubre las fases de una revisión y sus reintentos, sin
vencimiento, dentro del objetivo inicial y los dominios, IP o redes añadidos
manualmente al alcance. Un descubrimiento del modelo no amplía la autorización.

El despliegue de esta instalación activa la preferencia administrativa mediante
`NANDUTEST_PENTEST_AUTHORIZED_DEFAULT=1`. En el primer arranque se guarda
`nandutest.pentest_authorized_default=true` junto con el evento de auditoría.
Los siguientes arranques respetan el valor guardado y las suspensiones por tarea.
Las tareas creadas por orquestación no heredan automáticamente esta preferencia.

La cabecera y la pestaña Piloto automático muestran el permiso de pentest. El
administrador puede usar **Autorizar pentest siempre** o **Suspender autorización**;
el permiso se consulta al iniciar cada turno de planificación, conversación o
ejecución. Suspenderlo afecta a las nuevas ejecuciones; para detener trabajo ya
en curso se utiliza el control existente de pausa de la tarea.

`POST /api/tasks/{id}/pentest/authorization` recibe `{"enabled":true|false}` y
requiere el administrador verificado. Guarda el cambio y la auditoría en una sola
transacción. `GET /api/tasks/{id}/pilot` devuelve `pentest_authorization`, con el
alcance efectivo y su estado. El permiso no programa ni inicia pruebas, no altera
las reglas de intercepción, no confirma hallazgos ni acredita acceso o impacto.

La validación técnica autorizada se muestra como pendiente de ejecución y
evidencia. El piloto HTTPS conserva su frecuencia y autorización por dominio.
