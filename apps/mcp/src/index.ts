#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SqliteControlPlane, SshExecutor, allDemoScopesFromContracts } from "./deps.js";
import { createMcpServer } from "./server.js";

async function main(): Promise<void> {
  const controlPlane = new SqliteControlPlane();
  const executor = new SshExecutor((server) => controlPlane.resolveLoginCredential(server));
  controlPlane.setExecutor(executor);
  controlPlane.setScriptExecutor(executor);

  // Resuelve el token general de fallback (lo crea en el primer arranque).
  const general = controlPlane.ensureGeneralToken();

  const mcpServer = createMcpServer({
    controlPlane,
    identity: {
      subject: general.subject,
      scopes: new Set(allDemoScopesFromContracts),
      tokenId: general.id
    }
  });

  console.error("🛡️ secure-it MCP Server activo por stdio");
  await mcpServer.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "fallo interno";
  console.error(`secure-it no pudo iniciar: ${message}`);
  process.exitCode = 1;
});