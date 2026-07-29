#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SqliteControlPlane } from "@secure-it/control-plane";
import { createMcpServer } from "./server.js";

async function main(): Promise<void> {
  const controlPlane = new SqliteControlPlane();
  const mcpServer = createMcpServer({ controlPlane });

  console.error("🛡️ secure-it MCP Server activo por stdio");
  await mcpServer.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "fallo interno";
  console.error(`secure-it no pudo iniciar: ${message}`);
  process.exitCode = 1;
});
