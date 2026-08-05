import { DomainError } from "./errors.js";
import type { ActionDefinition, ServerRecord } from "./types.js";

/**
 * Resultado de ejecutar una acción tipada sobre un servidor objetivo.
 * El control plano sanitiza `stdout` antes de devolverlo al agente.
 */
export interface ExecutionOutcome {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  durationMs: number;
}

/**
 * Credencial de login resuelta internamente. El secreto vive solo en el
 * ejecutor y nunca se devuelve al agente ni se registra en esquemas de salida.
 */
export interface ResolvedCredential {
  username: string;
  secret: string;
  /** `password` para ssh2 con contraseña; `privateKey` para clave privada. */
  kind: "password" | "privateKey";
}

/**
 * Función pura que selecciona el secreto de login para un servidor objetivo.
 * La implementa el almacén (SQLite) y la inyecta el orquestador; el ejecutor
 * nunca accede a la base de datos ni expone el secreto al método `call`.
 */
export type CredentialResolver = (server: ServerRecord) => ResolvedCredential | null;

/**
 * Contrato del ejecutor de acciones tipadas. No acepta hosts, usuarios, opciones
 * SSH, credenciales ni scripts arbitrarios: solo el servidor inventariado, la
 * acción revisada del catálogo y sus parámetros validados por JSON Schema.
 * `execute_command` (scripts arbitrarios del agente) queda fuera de este
 * contrato para preservar la frontera de seguridad del proyecto.
 */
export interface ActionExecutor {
  readonly name: string;
  execute(
    server: ServerRecord,
    action: ActionDefinition,
    params: Record<string, unknown>
  ): Promise<ExecutionOutcome>;
}

export interface ScriptExecutor {
  readonly name: string;
  executeScript(
    server: ServerRecord,
    script: string,
    timeoutSeconds?: number
  ): Promise<ExecutionOutcome>;
}

/**
 * Caracteres permitidos en cualquier valor que se sustituya en una plantilla de
 * comando. Defense-in-depth: aunque `parameterSchema` acote con `enum`, bloquea
 * explícitamente metacaracteres de shell si una acción futura afloja el esquema.
 */
const SAFE_PARAM = /^[/A-Za-z0-9._@:=+,-]+$/;

/**
 * Construye el comando shell a partir de la plantilla de la acción sustituyendo
 * los marcadores `{clave}` por el parámetro validado. Lanza `INVALID_ARGUMENT`
 * ante cualquier valor fuera del charset seguro o placeholder sin resolver.
 */
export function buildCommand(
  action: ActionDefinition,
  params: Record<string, unknown>
): string {
  const template = action.commandTemplate;
  if (!template) {
    throw new DomainError("INVALID_ARGUMENT", `La acción ${action.id} no declara commandTemplate`);
  }
  let cmd = template;
  const placeholders = template.match(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g) ?? [];
  for (const marker of placeholders) {
    const key = marker.slice(1, -1);
    const raw = params[key];
    if (raw === undefined || raw === null) {
      throw new DomainError("INVALID_ARGUMENT", `Falta el parámetro '${key}' para ${action.id}`);
    }
    const value = String(raw);
    if (!SAFE_PARAM.test(value)) {
      throw new DomainError(
        "INVALID_ARGUMENT",
        `El parámetro '${key}' contiene caracteres no permitidos para ejecución real`
      );
    }
    cmd = cmd.split(marker).join(value);
  }
  if (action.elevatedPrivilege === true) {
    cmd = `sudo -n ${cmd}`;
  }
  return cmd;
}