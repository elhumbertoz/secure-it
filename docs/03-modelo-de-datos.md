# Modelo de datos

## Principio de separación

Hay tres almacenes lógicos y tres conjuntos de permisos:

| Almacén | Contiene | No contiene | Quién accede |
|---|---|---|---|
| Inventario | servidores, etiquetas, propietario, criticidad y estado | contraseñas, claves, tokens | plano de control; vista reducida para el agente |
| Mapeo de acceso | rol lógico, mecanismo y referencia opaca | valor del secreto | broker y administradores de seguridad |
| Gestor de secretos | credenciales heredadas, CA, políticas de emisión | historial de conversación | broker y backend administrativo; operadores de seguridad separados |

El cifrado de disco o de columnas es necesario, pero no convierte en segura una
credencial que la misma aplicación puede consultar. La separación de identidad,
API, red y permisos es el control principal.

## Entidades mínimas

### `servers`

- `id`: UUID interno, estable y no significativo.
- `name`: nombre canónico único.
- `environment`: `dev`, `test`, `staging` o `prod`.
- `owner_id`: equipo responsable.
- `criticality`: `low`, `medium`, `high` o `critical`.
- `lifecycle_state`: `pending`, `managed`, `quarantined` o `retired`.
- `connection_mode`: `local_agent`, `ssh_cert`, `cloud_api` u otro adaptador
  aprobado.
- `labels`: clasificación operativa validada.
- `created_at`, `updated_at`, `last_seen_at`.

### `management_endpoints`

- servidor, protocolo, dirección, puerto y zona de red;
- huella o identidad pública esperada del objetivo;
- salto o gateway lógico, si aplica.

Las direcciones pueden ser información sensible. No forman parte de la vista del
agente salvo necesidad explícita; el plano de control resuelve el UUID.

### `access_bindings`

- objetivo o selector de objetivos;
- mecanismo de autenticación;
- rol lógico y principal remoto;
- backend y referencia opaca del emisor;
- TTL máximo;
- estado y fechas de rotación.

Esta tabla **no tiene una columna para el valor de la credencial**. Tampoco debe
aparecer en copias, fixtures, volcados de soporte o telemetría.

### `access_profiles`

Define perfiles lógicos seleccionables desde MCP, como `linux-readonly-ssh-ca`:
modo, ambientes permitidos, TTL máximo y nivel de privilegio. La vista MCP expone
solo nombre y límites públicos. El plano de control resuelve el perfil a uno o más
bindings privados después del alta y la aprobación.

### `action_definitions`

Identificador, versión, esquema de parámetros, adaptador, privilegio, riesgo,
límites, política de salida y hash del artefacto ejecutable.

### `execution_requests`, `approvals` y `executions`

Conservan intención, manifiesto normalizado, decisión de política, aprobaciones,
estado, tiempos, resultado resumido y referencias a evidencias de auditoría. No
guardan secretos ni una copia irrestricta de toda la salida.

### `credential_rotation_jobs`

Registra binding, motivo, identidad solicitante, versión anterior y nueva mediante
identificadores no sensibles, estado, evidencia de verificación, tiempos y error
sanitizado. No contiene valores, respuestas del gestor de secretos ni comandos que
incluyan contraseñas.

## Esqueleto SQL orientativo

No es una migración lista para producción; documenta las invariantes que deberá
implementar el esquema real.

```sql
create table servers (
    id uuid primary key,
    name text not null unique,
    environment text not null
        check (environment in ('dev', 'test', 'staging', 'prod')),
    owner_id uuid not null,
    criticality text not null
        check (criticality in ('low', 'medium', 'high', 'critical')),
    lifecycle_state text not null
        check (lifecycle_state in ('pending', 'managed', 'quarantined', 'retired')),
    connection_mode text not null
        check (connection_mode in ('local_agent', 'ssh_cert', 'cloud_api')),
    labels jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_seen_at timestamptz
);

create table management_endpoints (
    id uuid primary key,
    server_id uuid not null references servers(id),
    protocol text not null,
    address text not null check (length(address) between 1 and 253),
    port integer not null check (port between 1 and 65535),
    network_zone text not null,
    expected_identity text not null,
    unique (server_id, protocol, address, port)
);

create table access_bindings (
    id uuid primary key,
    server_id uuid not null references servers(id),
    mechanism text not null
        check (mechanism in ('workload_mtls', 'ssh_ca', 'cloud_sts', 'legacy_secret')),
    remote_principal text not null,
    secret_backend text not null,
    credential_ref text not null,
    max_ttl_seconds integer not null check (max_ttl_seconds between 30 and 3600),
    enabled boolean not null default true,
    rotated_at timestamptz,
    unique (server_id, mechanism, remote_principal)
);

create table execution_requests (
    id uuid primary key,
    idempotency_key text not null unique,
    requester_subject text not null,
    action_id text not null,
    action_version integer not null,
    normalized_parameters jsonb not null,
    resolved_target_ids uuid[] not null,
    manifest_hash text not null unique,
    policy_hash text not null,
    risk text not null check (risk in ('read', 'low', 'high', 'critical')),
    status text not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);
```

`credential_ref` identifica una función de emisión o rol, no necesariamente la
ruta de una contraseña. Debe estar en un esquema privado sin permisos para el rol
del agente ni para consultas de soporte comunes.

## Vistas y roles

- `agent_catalog_reader`: solo una vista con `server_id`, alias, ambiente,
  criticidad, estado y etiquetas aprobadas. Sin endpoints ni acceso.
- `control_plane`: lee inventario, crea solicitudes y no lee valores secretos.
- `credential_broker`: lee bindings y solicita emisión; no modifica inventario.
- `executor`: recibe un manifiesto específico; no hace consultas SQL generales.
- `auditor`: lectura de eventos y configuración, sin ejecución.
- `security_admin`: administra emisores; no aprueba sus propias solicitudes.
- `credential_admin_api`: identidad exclusiva del backend de la consola; aplica
  permisos separados para crear, cambiar, revocar y revelar, sin acceso desde MCP.
- `rotation_worker`: ejecuta el protocolo de rotación para un binding específico;
  no lista ni exporta otros secretos.

La aplicación debe usar cuentas diferentes, conexiones diferentes y, cuando sea
posible, segmentos de red diferentes. Se aplican seguridad por filas, consultas
parametrizadas, TLS mutuo, copias cifradas y retención limitada.

## Alta y migración de credenciales heredadas

1. Un administrador registra el servidor y verifica su identidad fuera del agente.
2. La credencial heredada se introduce directamente al gestor de secretos mediante
   un canal administrativo; nunca por chat, ticket o variable del agente.
3. En el inventario se crea únicamente el binding al rol del broker.
4. Se prueba un acceso de solo lectura y se valida la huella del servidor.
5. Se instala confianza en una CA o un daemon local.
6. Se rota y elimina la credencial heredada.

Los volcados del inventario deben poder compartirse con desarrollo sin incluir
material que permita autenticarse.
