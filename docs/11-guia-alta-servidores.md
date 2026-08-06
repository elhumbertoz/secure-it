# Guía práctica: alta de servidores con contraseña

## A quién va dirigida

Esta guía es para un operador que tiene servidores que hoy se administran con
**usuario y contraseña** (no con certificados SSH ni agente local) y quiere
usarlos con `secure-it`. Es el caso de la «credencial heredada» descrito en
[servidor MCP](09-servidor-mcp.md).

La regla invariante del sistema es: **el agente nunca transporta secretos**.
Por eso la contraseña no entra por la herramienta `secureit.servers.add` del
agente, sino por la **consola administrativa humana**. Esta guía muestra cómo se
combinan ambos canales para dar de alta y operar el servidor.

## Modelo mental

```text
  Consola humana (sesión humana, scopes propios)        Agente MCP (sesión IA)
  -------------------------------------------------    ----------------------
  1. Importar la contraseña actual                      2. Registrar el servidor
  3. Aprobar/crear el binding lógico                        (sin credenciales)
  4. Confirmar la identidad del host
     (fingerprint / certificado de host)                5. Verificar enrolamiento
                                                        6. Ejecutar acciones
                                                        7. Rotar (ciego) y migrar
```

- La **consola humana** usa su propia aplicación, sesión y scopes. Sus tokens
  **no** son válidos ante MCP y viceversa (`docs/10:43-46`).
- El **agente** solo ve identificadores lógicos, estados y evidencia no sensible.

## Requisitos previos

- Tener la consola administrativa web accesible (se inicia automáticamente en **`http://127.0.0.1:4000`** al iniciar el agente con `npx -y @secure-it/mcp@beta`, o bien ejecutando manualmente `npm run admin` / `npx @secure-it/admin` en desarrollo).
- Para el paso 4, disponer del **fingerprint SSH real** del host, obtenido por
  un canal distinto al del agente (por ejemplo `ssh-keyscan` hecho por la persona
  en su terminal):

  ```bash
  ssh-keyscan -p <puerto> <host> 2>/dev/null | ssh-keygen -lf -
  # produce algo como: 256 SHA256:abcd…1234  (RSA)
  ```

- Un `access_profile_id` válido para el modo de conexión. En la demo existen
  `linux-readonly-local-agent` y `linux-readonly-ssh-ca`. Para credenciales
  heredadas se usa el perfil que el operador autorice para ese tipo de binding;
  si tu entorno no tiene uno, créalo o solicítalo antes de empezar. El perfil
  define cómo el executor se autentica contra el host durante la verificación y
  la ejecución.

## Paso 1 — Registrar o importar la credencial (Agente o Consola)

La credencial SSH (ya sea clave privada o contraseña de usuario) se puede registrar **directamente desde el Agente** mediante la herramienta MCP `secureit.credentials.add`, o bien por la consola administrativa web (`http://127.0.0.1:4000`) o el endpoint HTTP `POST /api/credentials`. El backend escribe el secreto directamente en el gestor de secretos cifrado y solo almacena el valor enmascarado `maskedValue: ••••••••`.

### Opción A: Vía Agente MCP (`secureit.credentials.add`) (Recomendado para el Agente)
El Agente puede ejecutar la llamada MCP con la credencial proporcionada por el usuario:
```json
{
  "alias": "ssh-prod-web-01",
  "type": "ssh_key",
  "owner": "infra-team",
  "environment": "prod",
  "exportable": true,
  "secret_value": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
}
```

### Opción B: Vía Interfaz Web
1. Abre tu navegador en **`http://127.0.0.1:4000`**.
2. Ingresa el **Token de Administración** (impreso en la terminal al ejecutar la consola).
3. Haz clic en **"+ Importar Credencial"**.
4. Completa el formulario y guarda.

### Opción C: Vía Petición HTTP (`POST /api/credentials`)
Forma del payload JSON:

```json
{
  "alias": "ssh-prod-web-01",
  "type": "ssh_key",
  "owner": "infra-team",
  "environment": "prod",
  "exportable": true,
  "secretValue": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
}
```

### Guía Detallada Campo por Campo para Credenciales SSH:

| Campo | Descripción y Valores | Ejemplo para SSH |
|---|---|---|
| **`alias`** | Nombre o identificador lógico que usará la consola humana para referirse a la credencial. **No** debe contener el secreto. | `"ssh-usuario-web01"` o `"ssh-key-prod-01"` |
| **`type`** | Tipo de credencial. Para claves SSH privadas usa **`ssh_key`**. Para contraseñas SSH tradicionales de usuario/password usa **`ssh_key`** (o **`db_password`** para contraseñas de texto). | `"ssh_key"` (Clave SSH) o `"db_password"` (Contraseña SSH) |
| **`owner`** | Identificador del equipo o persona propietaria de la credencial. | `"secops"`, `"infra"`, `"desarrollo"` |
| **`environment`** | Entorno en el que es válida la credencial (`prod`, `staging`, `dev`, `test`). | `"prod"` |
| **`exportable`** | Booleano (`true`/`false`). Si es `true`, un operador humano autorizado puede revelar/copiar la credencial en la consola web en caso de emergencia. | `true` |
| **`secretValue`** | **El Secreto Real**: la clave privada SSH (contenido completo del archivo `~/.ssh/id_rsa` o `id_ed25519`) o la contraseña SSH de login. | `"-----BEGIN OPENSSH PRIVATE KEY-----\n..."` o `"MiPasswordSSH123!"` |

Después de importar, la consola solo muestra el valor enmascarado `maskedValue: ••••••••` y metadatos. **Nunca** se devuelve el secreto en listados o llamadas del agente (`docs/10:54-72`).

## Paso 2 — Registrar el servidor (agente)

Desde el chat con el agente, pídele registrar el servidor. El agente llamará a
`secureit_servers_add` con campos no sensibles:

```json
{
  "name": "web-prod-01",
  "environment": "prod",
  "owner": "platform",
  "criticality": "high",
  "connection_mode": "local_agent",
  "management_endpoint": { "address": "192.0.2.10", "port": 22 },
  "expected_host_identity": "SHA256:<fingerprint obtenido en requisitos>",
  "access_profile_id": "<uuid del perfil autorizado>",
  "reason": "Alta del servidor web-prod-01 para el equipo de platform",
  "idempotency_key": "<uuid generado>"
}
```

La herramienta crea el registro en estado `pending`, con `bindingReady: false` e
`identityReady: false`. La respuesta del alta trae:

```json
{
  "server_id": "<uuid>",
  "state": "pending",
  "admin_action_required": true,
  "next_step": "Un administrador debe aprobar el binding y verificar la identidad fuera de MCP."
}
```

**Importante**: aquí NO se envía ni usuario ni contraseña. La herramienta rechaza
cualquier campo de credencial (`docs/09:187-188`, `spec/mcp-tools.json` con
`additionalProperties: false`).

## Paso 3 — Aprobar/crear el binding (consola humana)

Ahora se asocia la credencial importada en el paso 1 con el `access_profile_id`
del servidor registrado en el paso 2. Esto es lo que el sistema llama «aprobar
el binding» y **debe hacerlo un operador humano** en la consola
(`docs/09:280-289`):

- Crea/asigna el binding lógico entre la credencial (`alias: ssh-prod-web-01`) y
  el perfil de acceso usado en el alta.
- Marca el servidor como `bindingReady: true`.

> Estado de la demo: la asociación del binding se realiza en la consola
> administrativa mediante su flujo de credenciales/perfiles; si tu build no
> expone aún este paso, inténtalo desde el panel de «perfiles de acceso» de la
> consola. La opción `createCredential`/`rotateCredentialAdmin`/`revoke` están
> disponibles como endpoints REST en `apps/admin` (`server.ts:43-101`); la
> aceptación del binding se modela en el dominio con `bindingReady`.

## Paso 4 — Confirmar la identidad del host (consola humana)

El operador compara el `expected_host_identity` declarado en el alta con el
fingerprint/certificado **real** del host (obtenido por canal independiente) y
marca `identityReady: true`. El sistema **no** usa Trust On First Use: si la
identidad no coincide, el servidor queda bloqueado en `pending`.

## Paso 5 — Verificar enrolamiento (agente)

Desde el chat:

> «Verifica el enrolamiento del servidor web-prod-01»

El agente llama a `secureit_servers_enrollment_status` y luego, cuando
`binding_ready` e `identity_ready` estén en `true`, puede pedir
`secureit_servers_verify`. Esa verificación ejecuta una conexión de prueba
(ciego, sin exponer la contraseña al agente) y, si pasa, el servidor pasa a
`managed`.

Solo en estado `managed` se autorizan ejecuciones normales
(`docs/09:332`).

## Paso 6 — Operar (agente)

A partir de aquí el agente puede ejecutar acciones tipadas. Ejemplos:

> «Muestra el uso de disco en web-prod-01»
> «Revisa el estado del servicio nginx en el servidor web»

El agente llama a `secureit_ssh_execute_action` con `action_id`, versión,
`server_ids`, parámetros, motivo e idempotencia. **No acepta host, usuario ni
credencial**: el plano de control resuelve todo desde el inventario y las
políticas (`docs/09:219-223`). La contraseña importada en el paso 1 es usada
internamente por el executor/broker, nunca por el agente.

## Paso 7 — Rotar y migrar (agente + consola)

El sistema recomienda migrar de contraseña estática a mecanismos más seguros
(`docs/07:75-84`):

1. **Rotación ciega** desde el agente: «Rota el acceso de web-prod-01».
   `secureit_credentials_rotate` no acepta ni devuelve valores; el gestor genera
   un nuevo valor, lo instala, lo verifica y revoca el anterior
   (`docs/07:55-73`).
2. Repite o reemplaza el modo de conexión: transiciona `local_agent` →
   `ssh_cert` o identidad de carga cuando sea posible, para eliminar la
   dependencia de la contraseña compartida (deuda técnica temporal según
   `docs/07:83`).

## Notas de schematización (implementador)

- El tipo `CredentialType` actual no incluye un `ssh_password` específico. Para
  soportar el par(usuario, contraseña) sin ambigüedad, recomendado: ampliar el
  modelo con un campo `username` en `CredentialRecord` (sin cambiar la frontera
  del agente — la consola seguirá siendo el único canal de entrada). Alternativa
  provisional: codificar el usuario como etiqueta o prefijo del alias
  (p. ej. `ssh-prod-web-01:maint`), documentándolo explícitamente en tu
  despliegue.
- `connection_mode` es `local_agent | ssh_cert | cloud_api`. Para servidores
  heredados con contraseña, usa el perfil que tenga slash de password-acceso
  disponible; si no existe, crea un access profile equivalente y autorízalo en
  política antes de usarlo en el alta.

## Errores comunes

| Síntoma | Causa | Acción |
|---|---|---|
| `POLICY_DENIED`: el perfil no coincide con el modo | el `connection_mode` no coincide con el perfil | Usa un `access_profile_id` del mismo modo, o crea el perfil adecuado |
| `INVALID_STATE`: solo se verifican servidores pendientes | el servidor ya está `managed` | No necesitas verificar de nuevo |
| `admin_action_required: true` perpetuo | falta aprobar binding o identidad | Completa los pasos 3 y 4 en la consola humana |
| El agente dice «no puedo usar la contraseña» | comportamiento esperado | Importa la contraseña por la consola (paso 1), nunca por el chat |

## Resumen ejecutivo

- El usuario con servidores de usuario/contraseña **sí** puede usar `secure-it`.
- La contraseña entra **una vez** por la consola humana y nunca más se toca.
- El agente nunca ve ni pide la contraseña; solo opera con identificadores.
- Recomendado: rotar ciegamente y migrar a `ssh_cert`/identidad de carga para
  eliminar la contraseña estática.