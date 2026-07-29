import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpServer } from "../../apps/mcp/src/server.js";

const closeables: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(closeables.splice(0).map((value) => value.close()));
});

describe("servidor MCP", () => {
  it("filtra tools/list por scope y ejecuta una consulta estructurada", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({ scopes: new Set(["secureit:servers:read"]) });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const listed = await client.listTools();
    expect(listed.tools.map((tool) => tool.name).sort()).toEqual([
      "secureit.access_profiles.list",
      "secureit.servers.enrollment_status",
      "secureit.servers.get",
      "secureit.servers.list"
    ]);

    const result = await client.callTool({ name: "secureit.servers.list", arguments: {} });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ has_more: false });

    const denied = await client.callTool({
      name: "secureit.ssh.execute_command",
      arguments: {}
    });
    expect(denied.isError).toBe(true);
    expect(JSON.stringify(denied.content)).not.toContain("stack");
  });
});
