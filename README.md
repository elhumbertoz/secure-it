# Agente seguro para operar infraestructura

Este repositorio contiene la especificación inicial de un servidor MCP para que
Claude, Codex y otros clientes compatibles puedan inspeccionar y operar servidores
**sin recibir contraseñas, claves privadas ni tokens de infraestructura**.

## Estado de implementación

Ya existe una primera vertical ejecutable de demostración:

- workspace TypeScript con contratos derivados de `spec/mcp-tools.json`;
- las 12 herramientas MCP iniciales, filtradas por scopes;
- plano de control demo con inventario sintético, acciones tipadas, trabajos,
  idempotencia, hashing canónico y auditoría minimizada;
- rechazo de SSRF en altas demo y bloqueo de resultados con apariencia de secreto;
- migraciones PostgreSQL con esquemas y roles separados;
- política OPA de denegación por defecto y pruebas negativas;
- servidor MCP remoto stateless mediante Streamable HTTP del SDK oficial;
- validación de JWT OAuth/OIDC por JWKS (`iss`, `aud`, firma, `exp`, `sub` y
  scopes), catálogo filtrado y rechazo por defecto;
- allowlists de Host y Origin, límite de body, rate limit básico y endpoints de
  salud/readiness sin detalles de configuración;
- servidor MCP `stdio` limitado al desarrollo, sin acceso SSH ni credenciales
  reales.

La implementación actual **no es un piloto ni un sistema de producción**. El
ejecutor genera resultados sintéticos. El resource server OAuth está implementado,
pero el repositorio todavía no incluye un proveedor OIDC ni TLS/ingress. OpenBao,
aprobaciones humanas y la consola administrativa permanecen pendientes; por ello
no debe cargarse ninguna credencial real.

## Inicio rápido

Requisitos: Node.js 22 o posterior. **No requiere Docker ni instalación manual de base de datos.**

### Modo Zero-Config con `npx`

Puedes ejecutar el servidor MCP directamente sin instalar nada adicional ni levantar contenedores:

```bash
# Ejecución directa desde el directorio del proyecto:
npx .

# O mediante npm script:
npm run mcp
```

Los datos y cambios de estado (servidores, perfiles, auditoría) se persisten automáticamente en un archivo local SQLite en `~/.secure-it/secureit.db`.

#### Configuración para Claude Desktop / Cursor / VSCode MCP Client

Agrega el servidor MCP a tu archivo de configuración del cliente (ejemplo: `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "secure-it": {
      "command": "npx",
      "args": ["-y", "@secure-it/mcp"]
    }
  }
}
```

O apuntando a tu copia local del repositorio:

```json
{
  "mcpServers": {
    "secure-it": {
      "command": "npx",
      "args": ["."],
      "cwd": "/ruta/absoluta/secure-it"
    }
  }
}
```

### Streamable HTTP con OAuth/OIDC

El transporte remoto rechaza el arranque si falta configuración OIDC. Este ejemplo
solo usa dominios reservados y no incorpora tokens ni credenciales:

```bash
export SECUREIT_MODE=demo
export SECUREIT_HTTP_HOST=127.0.0.1
export SECUREIT_HTTP_PORT=3000
export SECUREIT_MCP_PUBLIC_URL=https://secure-it.example/mcp
export SECUREIT_OIDC_ISSUER=https://identity.example/realms/secure-it
export SECUREIT_OIDC_AUDIENCE=https://secure-it.example/mcp
export SECUREIT_OIDC_JWKS_URI=https://identity.example/realms/secure-it/protocol/openid-connect/certs
export SECUREIT_OIDC_AUTHORIZATION_URL=https://identity.example/realms/secure-it/protocol/openid-connect/auth
export SECUREIT_OIDC_TOKEN_URL=https://identity.example/realms/secure-it/protocol/openid-connect/token
export SECUREIT_ALLOWED_HOSTS=secure-it.example,127.0.0.1
export SECUREIT_ALLOWED_ORIGINS=https://client.example
npm run dev:mcp:http
```

El endpoint canónico es `POST /mcp`. `GET /mcp` y `DELETE /mcp` responden 405
porque esta fase usa transporte stateless; cada petición vuelve a validar el bearer
token. Los metadatos RFC 9728 están en
`/.well-known/oauth-protected-resource/mcp`. Las sondas son:

```bash
curl -fsS http://127.0.0.1:3000/healthz
curl -fsS http://127.0.0.1:3000/readyz
```

`/healthz` indica que el proceso responde. `/readyz` confirma únicamente que los
componentes locales inicializaron; todavía no prueba conectividad al IdP, OPA o
PostgreSQL y nunca devuelve URLs, issuer, audiencia ni otra configuración.

Variables HTTP opcionales: `SECUREIT_REQUEST_MAX_BYTES` (65 536),
`SECUREIT_RATE_LIMIT_WINDOW_MS` (60 000) y `SECUREIT_RATE_LIMIT_MAX` (60).
`SECUREIT_ALLOWED_HOSTS` es obligatorio al escuchar en `0.0.0.0` o `::`.
`SECUREIT_ALLOWED_ORIGINS` puede estar vacío para clientes no navegador; si una
petición incluye `Origin`, debe coincidir exactamente con la allowlist. HTTP sin
TLS en las URLs públicas u OIDC solo se acepta en loopback y únicamente en modo
demo. La audiencia OIDC debe coincidir exactamente con la URL pública canónica.

Para levantar PostgreSQL y OPA junto con las comprobaciones:

```bash
make demo
```

`make down` detiene esos servicios sin borrar datos. `make reset-demo` es la
única tarea destructiva y elimina únicamente el volumen Compose llamado
`secure-it-demo-postgres` después de comprobar el nombre del proyecto.

Identificadores útiles del inventario sintético:

- servidor web: `20000000-0000-4000-8000-000000000001`;
- perfil local de solo lectura: `10000000-0000-4000-8000-000000000001`;
- acción de ejemplo: `os.disk_usage`, versión `1`, con `mountpoint` igual a `/`,
  `/var` o `/srv`.

## Comandos de desarrollo

```bash
npm run build       # compila los tres workspaces
npm run lint        # verifica tipos estrictos
npm test            # contratos, dominio, seguridad e integración MCP
npm run dev:mcp:stdio # stdio, solo desarrollo demo
npm run dev:mcp:http  # Streamable HTTP con OAuth obligatorio
npm run start:mcp:http # ejecuta el build HTTP
make policy-test    # ejecuta las pruebas Rego con OPA
```

El rate limit actual usa memoria local y la IP observada por el proceso, con
`trust proxy` deshabilitado. No se comparte entre réplicas y no sustituye el límite
del ingress/WAF. Al desplegar detrás de un proxy, el proxy debe aplicar su propio
límite y conservar la allowlist de Host; esta fase no confía en
`X-Forwarded-For` enviado por clientes.

## Diseño de seguridad

Sí, es posible evitar que el modelo de IA conozca las credenciales. La condición
es separar el modelo del componente que establece la conexión:

1. El agente propone una acción estructurada sobre un identificador lógico.
2. El plano de control autentica al solicitante y evalúa políticas deterministas.
3. Las acciones de riesgo requieren aprobación humana.
4. Un ejecutor aislado recibe una capacidad efímera o delega la ejecución a un
   daemon en el servidor.
5. El agente solo recibe un resultado filtrado; nunca recibe el secreto ni una
   interfaz MCP para solicitarlo.

Esto no depende de pedirle al modelo que se niegue. Aunque un usuario autorizado
le diga “muéstrame la contraseña”, la herramienta carece de una operación para
leerla. Puede ofrecer, en cambio, probar el acceso, rotarlo o ejecutar una acción
permitida.

La base de datos de inventario **no debe contener valores de credenciales**. Solo
guarda metadatos de los servidores y, en una tabla privada, referencias opacas a
roles de acceso de un gestor de secretos. El modelo tampoco necesita ver esas
referencias.

Esto no impide ofrecer una **consola administrativa humana** para gestionar las
credenciales existentes. Esa consola vive fuera de MCP y de la frontera del
agente. Puede permitir agregar, sustituir, rotar o revocar credenciales y, cuando
el secreto sea exportable y la política lo autorice, revelarlo o copiarlo. La
lectura exige controles reforzados y nunca se refleja en herramientas MCP,
resultados, prompts ni trazas del agente.

## Límite de la garantía

"No conocer la credencial" significa que el secreto no aparece en el prompt, el
contexto, las herramientas, las variables de entorno, los archivos, las trazas ni
las respuestas visibles por el modelo. Un ejecutor de transporte puede usar una
clave o certificado efímero, pero debe vivir en otra frontera de seguridad y no
ser un proceso controlable por el modelo.

Si se permite al agente ejecutar comandos arbitrarios como `root`, la ausencia de
la credencial no evita que cause el mismo daño que esa credencial permitiría. La
seguridad depende además de mínimo privilegio, catálogo de acciones, límites de
alcance, aprobaciones y auditoría.

## Documentos

- [Objetivos, requisitos y límites](docs/01-requisitos-y-limites.md)
- [Arquitectura de referencia](docs/02-arquitectura.md)
- [Modelo de datos](docs/03-modelo-de-datos.md)
- [Modelo de amenazas y controles](docs/04-modelo-de-amenazas.md)
- [Contrato de acciones y API](docs/05-contrato-de-acciones.md)
- [Plan de implementación y operación](docs/06-plan-de-implementacion.md)
- [Recuperación y rotación de credenciales](docs/07-rotacion-de-credenciales.md)
- [Ejecución ciega y capacidades temporales](docs/08-ejecucion-ciega.md)
- [Diseño del servidor MCP](docs/09-servidor-mcp.md)
- [Interfaz administrativa de credenciales](docs/10-interfaz-administrativa-credenciales.md)
- [Catálogo MCP legible por máquina](spec/mcp-tools.json)
- [Fuentes técnicas](docs/FUENTES.md)

## Decisión recomendada para el primer piloto

- PostgreSQL para el inventario, sin secretos.
- Un gestor de secretos o CA para emitir accesos de corta duración.
- Un motor de políticas independiente del LLM.
- Un servidor MCP remoto mediante Streamable HTTP y OAuth, con herramientas
  filtradas por alcance. `stdio` se limita al desarrollo o a un puente local.
- Ejecutores desechables y aislados; preferentemente un daemon por servidor con
  identidad de carga de trabajo. SSH con certificados efímeros queda como camino
  de compatibilidad para sistemas existentes.
- Cinco servidores no críticos y acciones de solo lectura durante el piloto.

No se debe cargar ninguna credencial real hasta completar el modelo de amenazas,
las pruebas negativas y el procedimiento de emergencia descritos aquí.

Si una credencial ya fue expuesta a un agente, debe tratarse como comprometida:
revocarla o rotarla, invalidar las sesiones derivadas y revisar los registros. No
es suficiente borrarla del chat, y no debe esperarse a la rotación periódica.
