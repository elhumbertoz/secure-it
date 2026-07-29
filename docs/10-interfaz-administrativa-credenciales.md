# Interfaz administrativa de credenciales

## Decisión y propósito

`secure-it` debe disponer de una consola para que operadores humanos autorizados
administren las credenciales existentes sin recurrir al chat, a archivos locales o
a comandos ad hoc contra el gestor de secretos. Esta consola es un componente
separado del servidor MCP y no forma parte de las herramientas disponibles para el
agente.

La prohibición de leer secretos se aplica a la frontera del agente, no a todo ser
humano. Un administrador puede necesitar recuperar una contraseña para usarla en
un sistema heredado. Habilitar ese caso de manera explícita y auditable es más
seguro que empujar al operador hacia canales informales.

## Operaciones y canales

| Operación | Consola humana | MCP/agente (permitido por diseño) |
|---|---|---|
| Listar registros y metadatos autorizados | Sí | Solo metadatos mínimos y sin bindings privados |
| Importar el valor de una credencial existente | Sí | No |
| Solicitar generación y almacenamiento de una credencial | Sí | Sí, de forma ciega |
| Asociar un perfil o binding lógico aprobado | Sí | Sí, sujeto a política |
| Cambiar o rotar | Sí | Sí, de forma ciega |
| Probar acceso | Sí | Sí, sin devolver el valor |
| Revocar, deshabilitar o retirar un binding | Sí | Sí, si la política y aprobación lo permiten |
| Revelar o copiar el valor | Solo si es exportable y está autorizado | Nunca |
| Exportar secretos en lote | No | No |

“Agregar mediante MCP” significa pedir que la plataforma genere y almacene el
valor o asociar un perfil previamente aprobado. No significa pegar una contraseña,
clave privada o token en los argumentos de una herramienta. Si el administrador ya
conoce el valor que debe importarse, lo introduce directamente en la consola.

El catálogo MCP inicial solo define `secureit.credentials.rotate`. Las demás
operaciones ciegas de la tabla son extensiones previstas y deberán incorporarse
como herramientas tipadas, con política y esquemas propios, antes de considerarse
implementadas.

## Separación obligatoria

- La consola usa un origen, aplicación cliente, sesión y scopes distintos de MCP.
- Solo el backend administrativo se comunica con la API del gestor de secretos;
  el navegador no recibe tokens generales del gestor.
- Los tokens, cookies o identidades de servicio de MCP no son válidos ante la API
  administrativa. El backend rechaza identidades de agentes y cargas MCP.
- No se incluyen enlaces de revelado en resultados MCP, aprobaciones, tickets,
  notificaciones ni auditoría.
- La consola no ofrece API keys ni automatización reutilizable para revelar
  valores. La automatización usa las operaciones ciegas del plano de control.
- El permiso para crear, rotar o revocar se concede por separado del permiso
  `credential:reveal`.

## Experiencia de revelado y copia

Los listados muestran alias, tipo, propietario, alcance, estado, versión opaca,
última rotación y vencimiento, pero mantienen el valor enmascarado. Revelar o
copiar requiere una acción explícita sobre una sola credencial y:

1. reautenticación o step-up MFA resistente a phishing;
2. autorización por secreto, ambiente y rol, con denegación por defecto;
3. motivo o referencia de incidente cuando la política lo exija;
4. aprobación independiente para credenciales críticas;
5. sesión corta y nueva comprobación después de inactividad;
6. evento de auditoría inmediato y alerta para accesos sensibles.

La interfaz evita que el valor aparezca en URL, historial, telemetría, mensajes de
error, analítica, cachés compartidas o campos con autocompletado. Lo mantiene en
pantalla el menor tiempo posible y vuelve a enmascararlo automáticamente. Puede
intentar limpiar el portapapeles tras un intervalo y debe advertir al usuario, pero
esto es solo una reducción de riesgo: no impide que el sistema operativo, una
extensión o una aplicación conserve lo copiado.

No se revelan claves privadas de CA, claves protegidas por HSM/TPM, identidades de
carga no exportables ni capacidades efímeras de trabajos. Para ellas, la consola
solo ofrece estado, rotación, revocación y prueba de funcionamiento.

## Escritura y cambios

Al importar un secreto, el frontend lo envía una sola vez al backend administrativo
por un canal protegido. El backend valida tamaño y tipo, lo escribe directamente en
el gestor de secretos y descarta el cuerpo; no lo guarda en la base de inventario,
logs, colas, trazas ni eventos. La respuesta contiene únicamente un identificador
opaco y metadatos.

Cambiar, rotar, revocar o eliminar exige confirmar el alcance y mostrar el impacto
antes de ejecutar. En producción se prefieren flujos reversibles: versión pendiente,
prueba de acceso, promoción y revocación de la anterior. “Eliminar” retira primero
el binding y respeta la retención o recuperación del gestor; una destrucción
irreversible requiere autorización adicional.

## Auditoría y aceptación

La auditoría registra identidad humana, operación, credencial lógica, objetivos,
motivo, decisión de política, aprobador, instante y resultado, pero nunca el valor.
Como mínimo deben probarse estos casos:

- una sesión MCP no puede acceder a ninguna ruta administrativa;
- administrar o rotar no concede permiso de revelado;
- un listado o búsqueda nunca entrega valores;
- cada revelado y copia deja un evento, incluso si luego falla la visualización;
- copiar no coloca el secreto en telemetría ni en el DOM más tiempo del necesario;
- credenciales no exportables no tienen acción de revelado;
- los cambios y revocaciones respetan aprobación, idempotencia y recuperación;
- ningún valor aparece en logs, trazas, capturas automáticas o respuestas de error.
