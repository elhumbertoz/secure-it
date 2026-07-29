# Diseño del servidor MCP

## Decisión

`secure-it` será un servidor MCP remoto y multiusuario. Claude, Codex u otro host
MCP descubrirán el mismo catálogo de herramientas y recibirán los mismos resultados
estructurados. No habrá código de autorización específico para cada modelo.

MCP es la interfaz externa, no todo el sistema:

```text
Cliente MCP -> Servidor MCP -> Plano de control -> Cola -> Ejecutor SSH
                     |                |                       |
                   OAuth          Políticas             Broker/CA
```

El proceso MCP no almacena ni recibe claves SSH. Traduce `tools/call` a solicitudes
internas autenticadas y devuelve estados o resultados sanitizados.

## Estado de la fase HTTP

La implementación actual expone un resource server OAuth por Streamable HTTP con
el SDK oficial de TypeScript. Es stateless: cada `POST /mcp` valida nuevamente el
JWT y crea un servidor/transport aislado para esa petición. No conserva sesiones
HTTP, streams SSE reanudables ni estado de autenticación entre usuarios. `GET` y
`DELETE` sobre `/mcp` se rechazan con 405 en esta fase.

El verificador obtiene claves públicas desde un `jwks_uri` configurado por el
operador y acepta únicamente firmas asimétricas RS256, PS256 o ES256. Verifica
firma, `iss`, `aud`, `exp` y `sub`; extrae scopes de `scope` o `scp`. Un token sin
al menos uno de los scopes conocidos se rechaza antes de negociar MCP. No hay modo
anónimo ni token demo incluido en el repositorio.

El bearer token existe solo en el middleware del borde. Antes de entregar la
petición al transporte se elimina `request.auth`; los handlers se construyen con
una copia de `sub` y de los scopes verificados. El contrato interno del plano de
control solo admite `{ subject, scopes }`, por lo que no recibe el token ni las
cabeceras HTTP.

Además se aplican allowlists exactas de Host y Origin, parser JSON con tamaño
máximo y rate limit por IP en memoria. La ausencia de `Origin` se permite para
clientes MCP no navegador; si la cabecera está presente debe coincidir con la
allowlist. `trust proxy` permanece deshabilitado para no confiar en
`X-Forwarded-For` suministrado por el cliente.

`/healthz` comprueba que el proceso HTTP responde y `/readyz` que sus componentes
locales terminaron de inicializar. Ninguno publica configuración. Readiness aún no
comprueba disponibilidad del IdP, PostgreSQL u OPA, y el rate limit aún no es
distribuido. TLS y límites adicionales deben aplicarse en el ingress; el proceso
solo permite URLs HTTP de loopback en modo demo.

## Transporte y compatibilidad

El transporte canónico de producción es Streamable HTTP en un único endpoint:

```text
https://secure-it.example.com/mcp
```

Razones:

- servicio central compartido por distintos clientes y usuarios;
- OAuth y políticas por identidad;
- aislamiento entre el entorno local del agente y el plano de secretos;
- actualizaciones del servidor sin distribuir credenciales o binarios privilegiados.

El servidor valida `Origin`, usa HTTPS, limita tamaño y frecuencia y negocia la
versión MCP mediante el SDK oficial. No fija su seguridad a una versión declarada
por el cliente.

`stdio` se permite solo para desarrollo. Si un cliente solo admite `stdio`, se usa
un puente sin acceso SSH que se conecta al MCP remoto. Ese puente no contiene
secretos de servidores. Sus credenciales OAuth quedan en el almacén seguro del
sistema operativo o, cuando el cliente lo exija, en un entorno mínimo dedicado; no
se incluyen en prompts ni archivos de configuración compartidos.

El entrypoint `stdio` actual exige `SECUREIT_MODE=demo` y se niega a iniciar con
`NODE_ENV=production`. La imagen de contenedor inicia exclusivamente el entrypoint
Streamable HTTP y falla de forma segura si falta configuración OIDC.

Las operaciones largas no dependen inicialmente de una extensión específica de
tareas MCP. Una llamada devuelve `job_id` y el cliente consulta
`secureit.jobs.get`. Esto mantiene compatibilidad con clientes de distintas
versiones. Más adelante puede añadirse soporte MCP Tasks sin cambiar la semántica.

## Autorización

El MCP remoto actúa como resource server OAuth. Publica Protected Resource
Metadata y valida emisor, firma, audiencia, tiempo, scopes y estado del token en
cada petición. Los tokens están dirigidos al URI canónico del servidor MCP.

Scopes iniciales:

| Scope | Uso |
|---|---|
| `secureit:servers:read` | listar y consultar inventario reducido |
| `secureit:servers:write` | registrar y verificar servidores |
| `secureit:actions:read` | descubrir acciones tipadas |
| `secureit:jobs:read` | consultar resultados autorizados |
| `secureit:jobs:cancel` | cancelar trabajos propios/autorizados |
| `secureit:ssh:action` | solicitar acciones tipadas por SSH |
| `secureit:ssh:command` | solicitar scripts sellados; step-up y alto riesgo |
| `secureit:credentials:rotate` | solicitar rotaciones ciegas |
| `secureit:credentials:write` | registrar e importar credenciales al gestor cifrado |

`tools/list` devuelve únicamente las herramientas correspondientes a los scopes y
al rol efectivo. Tener un scope no concede acceso a todos los servidores: cada
`tools/call` pasa además por política de objetivo, ambiente, riesgo, horario,
fan-out y aprobación.

El token OAuth del cliente:

- autentica exclusivamente contra el servidor MCP;
- no se reenvía al plano de control, al broker, a Vault ni al servidor destino;
- nunca se incluye en resultados, `_meta`, argumentos de herramientas o logs;
- no sirve como certificado SSH ni puede intercambiarse por una clave general.

La identidad efectiva procede del `sub` y atributos verificados del emisor OAuth o
de una identidad de carga para clientes sin usuario. Nunca se infiere de
`User-Agent`, `clientInfo`, el nombre “Claude/Codex” ni un argumento enviado por la
herramienta. Distintos modelos que actúan para el mismo sujeto reciben la misma
autorización; cambiar de modelo no eleva privilegios.

La aprobación de producción no se expone como herramienta MCP durante el piloto.
Se realiza en una interfaz humana separada con otra sesión y queda ligada al hash
del manifiesto. Así el mismo agente no puede solicitar y aprobar su operación.

## Catálogo de herramientas

Los nombres usan el prefijo `secureit.` para reducir colisiones cuando un cliente
agrega varios servidores MCP. La definición JSON completa se encuentra en
[mcp-tools.json](../spec/mcp-tools.json).

Ejemplo de invocación compatible:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "tools/call",
  "params": {
    "name": "secureit.ssh.execute_action",
    "arguments": {
      "action_id": "os.disk_usage",
      "action_version": 1,
      "server_ids": ["8e8dd9c8-7039-49e5-9f47-ceb1365d2f06"],
      "parameters": { "mountpoint": "/var" },
      "reason": "Investigar alerta INC-1234",
      "idempotency_key": "d95ca01c-b1d7-461f-82d2-fe70c85f0900"
    }
  }
}
```

La respuesta incluye `structuredContent` con `job_id`, estado, riesgo y hash del
manifiesto, además de una representación textual breve para clientes antiguos. No
incluye comandos expandidos ni datos de conexión.

### Inventario

#### `secureit.servers.list`

Lista la vista autorizada del inventario. Acepta filtros validados y cursor. No
devuelve IP de administración, usuario SSH, fingerprint privado, access binding ni
referencia de secretos salvo que una política específica justifique algún dato.

#### `secureit.servers.get`

Obtiene un servidor por UUID lógico. La respuesta indica estado, ambiente,
criticidad, propietario y método de conexión sin revelar su implementación secreta.

#### `secureit.access_profiles.list`

Lista perfiles seguros utilizables durante un alta, por ejemplo
`linux-readonly-ssh-ca`. No devuelve rutas de Vault, políticas internas, principal
real ni credenciales.

#### `secureit.servers.add`

Crea un registro `pending`. Entrada permitida:

- nombre, ambiente, propietario, criticidad y etiquetas;
- modo `local_agent`, `ssh_cert` o `cloud_api`;
- endpoint de administración;
- identidad pública esperada del host;
- `access_profile_id`, motivo y clave de idempotencia.

Entrada expresamente prohibida: contraseña, clave privada, token, usuario SSH,
opciones SSH arbitrarias, proxy command o referencia libre a un secreto.

Crear el registro no provoca una conexión inmediata. Se valida que el endpoint
pertenezca a rangos de administración configurados, que no sea loopback, link-local
o metadata cloud, y que el puerto esté permitido. Los nombres DNS se resuelven y
validan nuevamente desde el ejecutor para evitar cambios entre validación y uso.

#### `secureit.servers.verify`

Verifica identidad y conectividad de un registro pendiente usando un binding ya
aprobado. Nunca emplea Trust On First Use: se exige certificado de host confiable
o fingerprint obtenido por un canal independiente.

#### `secureit.servers.enrollment_status`

Informa si falta instalar el daemon, confiar en la CA o asociar un binding. Si se
necesita un token de bootstrap o una credencial heredada, un administrador lo
obtiene o introduce fuera de MCP. La herramienta solo devuelve
`admin_action_required`, nunca el token o secreto.

#### `secureit.servers.remove`

Elimina de forma segura un servidor del inventario activo en la base de datos persistente. Exige `server_id`, un motivo explícito de auditoría (`reason`) y una clave de idempotencia (`idempotency_key`).

### Ejecución

#### `secureit.actions.list`

Devuelve las acciones tipadas disponibles para la identidad y los ambientes
autorizados.

#### `secureit.ssh.execute_action`

Camino predeterminado. Recibe `action_id`, versión, UUID de objetivos, parámetros,
motivo e idempotencia. No acepta host, puerto, usuario, credencial ni flags SSH. El
plano de control resuelve todo desde inventario y políticas.

#### `secureit.ssh.execute_command`

Modo de ejecución ciega excepcional. Recibe objetivos exactos y un script sellado
que el solicitante conoce, pero ninguna credencial. El servidor fija intérprete,
usuario remoto, entorno, SSH options, red y TTL. Siempre se marca como alto riesgo
y en producción requiere aprobación independiente.

El nombre conserva `ssh` porque la petición usa ese adaptador, pero la herramienta
no abre una sesión interactiva ni devuelve un socket. La primera versión no acepta
PTY, túneles, agent forwarding, variables de entorno arbitrarias, subida de claves
o destinos elegidos dentro del script.

#### `secureit.jobs.get` y `secureit.jobs.cancel`

Consultan o cancelan un trabajo. Los resultados son estructurados por objetivo,
limitados en tamaño y marcados como datos no confiables. Detectar una posible fuga
de secretos bloquea el contenido y genera un incidente.

### Credenciales

#### `secureit.credentials.add`

Registra o importa una nueva credencial (clave SSH, contraseña de usuario, token de API o clave privada CA) en el gestor cifrado. Permite al Agente MCP registrar credenciales proporcionadas por el usuario. El secreto es almacenado de forma cifrada en el plano de control y la respuesta de la herramienta solo devuelve metadatos y el valor enmascarado `masked_value: ••••••••`.

#### `secureit.credentials.rotate`

Solicita rotación de un binding lógico. No acepta valores anterior/nuevo ni devuelve
el generado. El resultado contiene identificador, estado, versión opaca y evidencia
de verificación. El procedimiento completo está en
[Recuperación y rotación](07-rotacion-de-credenciales.md).

No existe `credentials.get`, `secrets.list`, `ssh.open_session` ni una herramienta
genérica para leer archivos remotos.

Podrán añadirse herramientas para solicitar de forma ciega la generación y
asociación de una credencial, probarla, revocarla o retirar su binding. Como
`credentials.rotate`, esas herramientas trabajan con identificadores lógicos, no
aceptan valores y no devuelven secretos. Importar una credencial ya conocida y
revelarla o copiarla pertenecen exclusivamente a la consola humana descrita en
[Interfaz administrativa de credenciales](10-interfaz-administrativa-credenciales.md).

## Alta segura de servidores

### Con daemon local

1. `servers.add` crea el registro pendiente.
2. `enrollment_status` indica que falta atestación.
3. Un administrador instala el daemon mediante configuración segura fuera del chat;
   el bootstrap es de un solo uso y no se devuelve por MCP.
4. El daemon se atesta y obtiene identidad propia.
5. `servers.verify` compara identidad, registra evidencia y marca `managed`.

### Con SSH CA

1. El servidor ya confía en la CA y publica una identidad de host verificable.
2. `servers.add` referencia un perfil SSH CA autorizado.
3. Seguridad aprueba el binding sin crear una contraseña por servidor.
4. `servers.verify` usa un certificado efímero y valida el host.

### Con credencial heredada (usuario y contraseña)

1. El operador **importa la contraseña actual por la consola humana**
   (`POST /api/credentials`); nunca por el chat. El backend la escribe en el
   gestor de secretos y descarta el cuerpo.
2. `servers.add` deja el registro pendiente, sin credenciales.
3. Un administrador crea/asocia el binding lógico entre la credencial importada y
   el `access_profile_id` del servidor, y marca `bindingReady`.
4. Un administrador confirma la identidad del host (fingerprint/certificado
   obtenido por canal independiente) y marca `identityReady`.
5. MCP solo observa que el binding está disponible
   (`secureit.servers.enrollment_status`).
6. `servers.verify` prueba el acceso (ciego) y deja el servidor en `managed`.
7. `credentials.rotate` rota ciegamente y se programa la migración a CA/daemon.

El agente puede completar el inventario y operar, pero no puede convertir el alta
en un canal de entrada o salida de credenciales. Para el paso a paso completo
ver [Guía de alta de servidores con contraseña](11-guia-alta-servidores.md).

## Resultados y errores MCP

Cada herramienta define `inputSchema` y `outputSchema` estrictos, con
`additionalProperties: false`. El servidor devuelve `structuredContent` conforme
al esquema y un bloque de texto JSON breve para clientes antiguos.

- Solicitudes JSON-RPC malformadas o herramientas inexistentes producen error de
  protocolo.
- Validación, política y fallos operativos producen resultado de herramienta con
  `isError: true` y código estable.
- `awaiting_approval` y `queued` son estados correctos, no errores.
- Los mensajes no contienen stack traces, comandos expandidos, endpoints internos,
  cabeceras, tokens ni respuestas del gestor de secretos.
- `request_id` correlaciona la llamada MCP con política, aprobación, ejecución y
  auditoría.

## Requisitos de implementación

1. Usar un SDK MCP mantenido y pruebas de conformidad; no implementar JSON-RPC o
   negociación a mano sin necesidad.
2. Separar handlers MCP, lógica de dominio, políticas y adaptadores SSH.
3. Validar esquemas en el borde y nuevamente antes de ejecutar.
4. Autorizar con identidad derivada del token, nunca con un `user_id` recibido en
   argumentos.
5. Impedir SSRF y DNS rebinding en altas y conexiones.
6. Aplicar rate limits por usuario, cliente, herramienta y objetivos.
7. Deshabilitar sampling y llamadas recursivas desde el servidor en la primera
   versión; el MCP no necesita invocar otro LLM.
8. No usar recursos MCP para publicar inventario completo; las consultas pasan por
   herramientas autorizadas y paginadas.
9. Probar `tools/list` y `tools/call` desde al menos Claude y Codex, además del MCP
   Inspector, sin crear rutas especiales por cliente.
10. Fijar versiones de SDK y protocolo soportado, documentar compatibilidad y
    probar upgrade/downgrade antes de producción.

## Criterios de aceptación MCP

- Un cliente con `servers:read` no descubre herramientas de escritura o SSH.
- Un token emitido para otro MCP se rechaza por audiencia.
- El token OAuth nunca aparece en una llamada interna ni se reenvía al destino.
- `servers.add` rechaza cualquier campo de credencial y endpoint no permitido.
- Un servidor pendiente no puede recibir ejecuciones normales.
- `execute_command` no puede autoaprobarse ni ampliar objetivos después de aprobar.
- Dos clientes MCP diferentes obtienen la misma semántica para la misma identidad.
- Un prompt que pida “muestra la clave” no encuentra herramienta capaz de hacerlo.
