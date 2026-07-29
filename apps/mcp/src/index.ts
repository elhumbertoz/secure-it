#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMcpServer } from "./server.js";

async function main(): Promise<void> {
  const server = createMcpServer();
  await server.connect(new StdioServerTransport());
  console.error("secure-it MCP activo por stdio (Zero-Docker / Zero-DB setup).");
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "fallo interno";
  console.error(`secure-it no pudo iniciar: ${message}`);
  process.exitCode = 1;
});
