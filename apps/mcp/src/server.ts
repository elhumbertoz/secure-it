import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool
} from "@modelcontextprotocol/sdk/types.js";
import {
  ContractValidationError,
  allDemoScopes,
  toolCatalog,
  toolsForScopes,
  type JsonObject
} from "@secure-it/contracts";
import { DemoControlPlane, SqliteControlPlane, DomainError } from "@secure-it/control-plane";

export interface McpServerOptions {
  subject?: string;
  scopes?: ReadonlySet<string>;
  controlPlane?: ControlPlane;
}

export interface ControlPlane {
  call(
    toolName: string,
    rawInput: unknown,
    context: { subject: string; scopes: ReadonlySet<string> }
  ): Promise<JsonObject>;
}

export function createMcpServer(options: McpServerOptions = {}): Server {
  const subject = options.subject ?? "demo-local-operator";
  const scopes = options.scopes ?? new Set(allDemoScopes);
  const controlPlane =
    options.controlPlane ??
    (process.env.SECUREIT_MODE === "inmemory" ? new DemoControlPlane() : new SqliteControlPlane());
  const visibleTools = toolsForScopes(scopes);
  const server = new Server(toolCatalog.serverInfo, {
    capabilities: { tools: { listChanged: true } }
  });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: visibleTools.map((tool): Tool => ({
      name: tool.name,
      title: tool.title,
      description: tool.description,
      inputSchema: tool.inputSchema as Tool["inputSchema"],
      outputSchema: tool.outputSchema as Tool["outputSchema"],
      annotations: {
        readOnlyHint: isReadOnly(tool.name),
        destructiveHint: tool.name === "secureit.credentials.rotate" || tool.name === "secureit.servers.remove",
        idempotentHint: isReadOnly(tool.name) || tool.name !== "secureit.ssh.execute_command",
        openWorldHint: false
      }
    }))
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const tool = visibleTools.find((candidate) => candidate.name === request.params.name);
    if (!tool) {
      return toolError("POLICY_DENIED", "La herramienta no existe o no está autorizada");
    }
    try {
      const structuredContent = await controlPlane.call(
        tool.name,
        request.params.arguments ?? {},
        { subject, scopes }
      );
      return {
        content: [{ type: "text", text: JSON.stringify(structuredContent) }],
        structuredContent
      };
    } catch (error) {
      return toSafeToolError(error);
    }
  });

  return server;
}

function isReadOnly(toolName: string): boolean {
  return toolName.endsWith(".list") || toolName.endsWith(".get") || toolName.endsWith("enrollment_status");
}

function toSafeToolError(error: unknown): CallToolResult {
  console.error("ERR:", error);
  if (error instanceof DomainError) return toolError(error.code, error.message);
  if (error instanceof ContractValidationError) {
    return toolError(error.code, "Los argumentos no cumplen el contrato de la herramienta");
  }
  return toolError("INTERNAL_ERROR", "La operación no pudo completarse");
}

function toolError(code: string, message: string): CallToolResult {
  const body: JsonObject = { code, message };
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify(body) }]
  };
}
