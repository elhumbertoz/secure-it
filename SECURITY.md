# Política de seguridad

## Estado y uso previsto

La versión 0.1.x debe considerarse preliminar. Use datos sintéticos en demos y
complete una revisión de seguridad independiente antes de conectarla a sistemas
de producción. El bootstrap de una base persistente exige
La instalación interactiva crea la cuenta en la consola local y genera una clave
maestra local con permisos `0600`. En despliegues gestionados se pueden inyectar
`SECUREIT_ADMIN_PASSWORD` y `SECUREIT_MASTER_KEY` desde un gestor de secretos.

## No use secretos reales en la demostración

La implementación actual usa exclusivamente datos sintéticos y rangos reservados
para documentación. No introduzca contraseñas, claves privadas, tokens, cookies,
certificados privados ni credenciales cloud en issues, pruebas, fixtures, variables
de entorno o herramientas MCP.

Si una credencial aparece en un prompt, log, traza, commit o resultado del agente,
trátela como comprometida: revoque o rote la credencial, invalide las sesiones
derivadas y revise su uso. Borrarla del historial no remedia la exposición.

## Reporte

No publique detalles de una vulnerabilidad explotable en un issue público. En un
repositorio derivado, configure primero un canal privado de seguridad y publique
su contacto aquí antes de aceptar usuarios o infraestructura real.

Un reporte útil incluye la versión, el límite de confianza afectado, pasos de
reproducción con valores sintéticos y el impacto esperado. Nunca adjunte secretos
ni datos de objetivos reales.

## Alcance actual

Son comprobables el contrato MCP, la validación local de JWT OAuth/OIDC, el
filtrado por scopes, las defensas del endpoint Streamable HTTP, la política demo de
endpoints, la idempotencia, la minimización de auditoría y el filtrado de salida.
No se hacen todavía afirmaciones de seguridad sobre disponibilidad o configuración
de un proveedor OIDC real, TLS/ingress, rate limiting distribuido, OpenBao, una
consola humana, aprobación externa ni ejecución sobre infraestructura real.
