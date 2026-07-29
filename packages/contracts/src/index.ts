import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Ajv2020Import, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsImport from "ajv-formats";

export type JsonObject = Record<string, unknown>;

export interface ToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: JsonObject;
  outputSchema: JsonObject;
}

interface ToolCatalogDocument {
  serverInfo: { name: string; version: string };
  capabilities: JsonObject;
  tools: ToolDefinition[];
}

const catalogPath = fileURLToPath(new URL("../../../spec/mcp-tools.json", import.meta.url));
const parsedCatalog = JSON.parse(readFileSync(catalogPath, "utf8")) as ToolCatalogDocument;

export const toolCatalog = Object.freeze(parsedCatalog);

const requiredScopes: Readonly<Record<string, string>> = Object.freeze({
  "secureit.servers.list": "secureit:servers:read",
  "secureit.servers.get": "secureit:servers:read",
  "secureit.access_profiles.list": "secureit:servers:read",
  "secureit.servers.add": "secureit:servers:write",
  "secureit.servers.enrollment_status": "secureit:servers:read",
  "secureit.servers.verify": "secureit:servers:write",
  "secureit.servers.remove": "secureit:servers:write",
  "secureit.actions.list": "secureit:actions:read",
  "secureit.ssh.execute_action": "secureit:ssh:action",
  "secureit.ssh.execute_command": "secureit:ssh:command",
  "secureit.jobs.get": "secureit:jobs:read",
  "secureit.jobs.cancel": "secureit:jobs:cancel",
  "secureit.credentials.rotate": "secureit:credentials:rotate",
  "secureit.credentials.add": "secureit:credentials:write"
});

export const allDemoScopes = Object.freeze([...new Set(Object.values(requiredScopes))]);

export function requiredScopeFor(toolName: string): string {
  const scope = requiredScopes[toolName];
  if (!scope) throw new Error(`No hay un scope registrado para ${toolName}`);
  return scope;
}

export function toolsForScopes(scopes: ReadonlySet<string>): ToolDefinition[] {
  return toolCatalog.tools.filter((tool) => scopes.has(requiredScopeFor(tool.name)));
}

interface AjvLike {
  compile(schema: object): ValidateFunction;
  errorsText(errors?: ErrorObject[] | null, options?: { separator?: string }): string;
}

const Ajv2020 = Ajv2020Import as unknown as new (options: object) => AjvLike;
const addFormats = addFormatsImport as unknown as (instance: AjvLike) => void;
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);

const inputValidators = new Map<string, ValidateFunction>();
const outputValidators = new Map<string, ValidateFunction>();
for (const tool of toolCatalog.tools) {
  inputValidators.set(tool.name, ajv.compile(tool.inputSchema));
  outputValidators.set(tool.name, ajv.compile(tool.outputSchema));
}

export class ContractValidationError extends Error {
  readonly code = "INVALID_ARGUMENT";

  constructor(
    readonly toolName: string,
    readonly side: "input" | "output",
    readonly validationErrors: ErrorObject[]
  ) {
    super(`${toolName}: ${side} no cumple el contrato`);
    this.name = "ContractValidationError";
  }
}

function validate(
  validators: ReadonlyMap<string, ValidateFunction>,
  toolName: string,
  side: "input" | "output",
  value: unknown
): asserts value is JsonObject {
  const validator = validators.get(toolName);
  if (!validator) throw new Error(`Herramienta desconocida: ${toolName}`);
  if (!validator(value)) {
    throw new ContractValidationError(toolName, side, [...(validator.errors ?? [])]);
  }
}

export function validateToolInput(toolName: string, value: unknown): asserts value is JsonObject {
  validate(inputValidators, toolName, "input", value);
}

export function validateToolOutput(toolName: string, value: unknown): asserts value is JsonObject {
  validate(outputValidators, toolName, "output", value);
}

export function getTool(toolName: string): ToolDefinition {
  const tool = toolCatalog.tools.find((candidate) => candidate.name === toolName);
  if (!tool) throw new Error(`Herramienta desconocida: ${toolName}`);
  return tool;
}

export function validateJsonSchema(schema: JsonObject, value: unknown, label = "schema"): void {
  const validator = ajv.compile(schema);
  if (!validator(value)) {
    throw new Error(`${label}: ${ajv.errorsText(validator.errors, { separator: "; " })}`);
  }
}
