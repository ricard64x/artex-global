# Ñandutest — piloto continuo y verificación controlada

La automatización tiene dos planos separados:

1. Auditoría continua del código en GitHub Actions: diariamente analiza un
   checkout autorizado del repositorio mediante Semgrep y Trivy. Los escáneres
   se ejecutan SIN red y los datos públicos de Actions contienen solamente
   métricas agregadas. Las imágenes y la base Trivy se descargan antes de la
   fase aislada. Si falla un escáner, el ciclo queda incompleto.
2. Piloto de producción por tarea: requiere superadministrador, coincidencia
   exacta del dominio con el alcance de la tarea, regla de permiso explícito,
   ticket vigente de hasta siete días y límites de intervalo. Una aprobación
   pasiva solo permite HTTPS HEAD. Nunca autoriza un pentest intrusivo.

La prueba de laboratorio nandutest_pilot_lab.py --authorize-lab corre una
API efímera en 127.0.0.1, realiza ocho fases y usa una credencial sintética
para comprobar acceso permitido y denegación de acceso inválido. No hace
peticiones a dominios externos. Los resultados llevan siempre:
real_target_tested=false y real_access_demonstrated=false.
Es una prueba verificable del orquestador, NO del acceso a una empresa.

Aprendizaje: Getangiru almacena resúmenes por tarea. Solo memoria
confirmada por un revisor humano se recupera como contexto fiable.
Esto mejora la reutilización supervisada de evidencias, pero NO entrena
automáticamente los pesos de Qwen.

Aún no hay prueba de que Ñandutest complete las fases de acceso, escalada
o impacto en un sistema empresarial. Para esas fases se necesita autorización
nueva, con cuenta y entorno de ensayo, objetivos y endpoints explícitos,
ventana, límites, persona responsable, revocación y plan de reversión.
El cron nunca ejecuta pruebas de intrusión contra sitios externos.

Validación del laboratorio:
python3 -m unittest scripts/test_nandutest_pilot_lab.py -v
python3 scripts/nandutest_pilot_lab.py --authorize-lab

Reversión: quitar schedule de la acción, o revocar la autorización de cada
tarea en la pestaña Piloto continuo. No modificar otros proyectos.
