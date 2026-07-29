#!/usr/bin/env node
import { loadHttpServerConfig } from "./config.js";
import { createHttpMcpApp, listenHttpMcp } from "./http.js";

async function main(): Promise<void> {
  const config = loadHttpServerConfig();
  const server = await listenHttpMcp(createHttpMcpApp({ config }), config);
  console.error("secure-it MCP demo activo por Streamable HTTP; no use credenciales reales");

  const shutdown = (): void => {
    server.close((error) => {
      if (error) process.exitCode = 1;
    });
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "fallo interno";
  console.error(`secure-it no pudo iniciar: ${message}`);
  process.exitCode = 1;
});
