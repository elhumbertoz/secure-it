# Contrato de acciones y API

## Principio

El agente elige una operación; no escribe el comando que la implementa. Cada
operación es versionada, revisada y ejecutada mediante un adaptador determinista.

## Ejemplo de definición

```yaml
id: os.disk_usage
version: 1
description: Consulta el uso de un punto de montaje local.
risk: read
executor: local-plugin
artifact:
  digest: sha256:REEMPLAZAR_POR_DIGEST_REAL
parameters:
  type: object
  additionalProperties: false
  required: [mountpoint]
  properties:
    mountpoint:
      type: string
      enum: ["/", "/var", "/srv"]
command:
  argv: ["/usr/bin/df", "-P", "--", "{{ mountpoint }}"]
runtime:
  user: infra-readonly
  privileged: false
  timeout_seconds: 20
  network: none
limits:
  max_targets: 20
  max_stdout_bytes: 65536
  max_stderr_bytes: 16384
output:
  parser: df-posix-v1
  classification: internal
approval:
  dev: none
  test: none
  staging: requester-confirmation
  prod: independent-operator
```

Las plantillas no se interpolan en una cadena de shell. El ejecutor valida y
construye un vector de argumentos. En acciones complejas se prefiere un plugin
compilado o script revisado y fijado por digest.

## Solicitud del agente

```http
POST /v1/execution-requests
Idempotency-Key: 018fe2c8-...
Content-Type: application/json
```

```json
{
  "action": { "id": "os.disk_usage", "version": 1 },
  "target_selector": {
    "environment": "test",
    "labels": { "role": "web" }
  },
  "parameters": { "mountpoint": "/var" },
  "reason": "Investigar alerta de capacidad INC-1234"
}
```

El agente no envía IP, usuario remoto, binding, comando, TTL, rol de secretos ni
opciones SSH. El servidor los resuelve desde configuración confiable.

## Respuesta previa a ejecución

```json
{
  "request_id": "7acb9df1-...",
  "status": "awaiting_approval",
  "risk": "read",
  "targets": {
    "count": 3,
    "aliases": ["web-test-01", "web-test-02", "web-test-03"]
  },
  "approval": {
    "required": true,
    "kind": "requester-confirmation",
    "expires_at": "2026-07-28T17:10:00Z"
  },
  "manifest_hash": "sha256:..."
}
```

La aprobación referencia `manifest_hash`; no acepta un texto ambiguo como “sí”.
Una persona no recibe del agente un enlace fabricado: consulta la solicitud en una
interfaz autenticada del plano de control.

## API interna mínima

Estas rutas son internas al plano de control. Los agentes no las consumen
directamente; acceden a contratos equivalentes mediante las herramientas definidas
en [Diseño del servidor MCP](09-servidor-mcp.md).

- `GET /v1/catalog/actions`: operaciones disponibles para la identidad actual.
- `GET /v1/catalog/targets`: vista reducida y filtrada de objetivos.
- `POST /v1/execution-requests`: crea y evalúa una solicitud idempotente.
- `GET /v1/execution-requests/{id}`: estado y resumen autorizado.
- `POST /v1/execution-requests/{id}/cancel`: solicita cancelación.
- `POST /v1/approvals`: interfaz humana separada; no se expone como herramienta al
  agente durante el piloto.

No existe endpoint de secretos accesible por el agente o por una sesión MCP. Los
endpoints internos del broker aceptan un manifiesto firmado y una identidad de
ejecutor atestada, no un nombre de ruta arbitrario. La API de la consola humana es
otra superficie, con identidad y permisos propios, descrita en
[Interfaz administrativa de credenciales](10-interfaz-administrativa-credenciales.md).

La rotación utiliza `POST /v1/credential-rotations` con binding lógico, selector y
motivo. El contrato no admite campos `old_secret`, `new_secret`, `password`,
`private_key` o equivalentes. La respuesta expone únicamente estado, identificador
de versión no sensible, fecha de verificación y próxima rotación.

Una interfaz opcional `POST /v1/blind-executions` se reserva para el modo
controlado descrito en [Ejecución ciega](08-ejecucion-ciega.md). No es un atajo que
omita validación, política, aprobación o auditoría.

## Entrada, salida y errores

- JSON Schema estricto, tamaño limitado y `additionalProperties: false`.
- Valores se normalizan antes de política y firma.
- Los selectores se resuelven una vez; una colección vacía o demasiado grande se
  rechaza.
- La salida se parsea a un tipo conocido. La salida cruda se conserva solo si la
  clasificación y retención lo permiten, fuera del contexto del modelo.
- Se eliminan controles de terminal y se truncan campos y número de registros.
- Un detector de secretos genera un incidente y bloquea la devolución, pero no se
  considera la defensa primaria.
- Los errores externos se convierten a códigos estables; no se devuelven comandos,
  rutas internas, tokens, cabeceras ni trazas.

## Reglas de autorización de ejemplo

La política recibe identidad, acción, parámetros normalizados, objetivos resueltos,
hora, riesgo y estado operativo. Devuelve una decisión estructurada con límites,
no solo `true` o `false`.

- negar si algún objetivo está retirado o en cuarentena;
- negar si `max_targets` se supera;
- negar acciones no incluidas en el rol del usuario;
- exigir aprobador independiente en producción;
- impedir que solicitante y aprobador sean la misma identidad cuando el riesgo es
  alto;
- reducir concurrencia y ejecutar primero un canario;
- negar si no puede escribirse auditoría;
- negar políticas o acciones cuya versión no coincida con el manifiesto.

La decisión completa y la versión del paquete de políticas se registran antes de
despachar el trabajo.
