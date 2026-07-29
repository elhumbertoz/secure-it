import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpServer } from "../../apps/mcp/src/server.js";
import { DemoControlPlane, SqliteControlPlane } from "@secure-it/control-plane";

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

  it("permite registrar credenciales si se posee el scope secureit:credentials:write", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
      scopes: new Set(["secureit:credentials:write"]),
      controlPlane: new DemoControlPlane()
    });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const result = await client.callTool({
      name: "secureit.credentials.add",
      arguments: {
        alias: "ssh-prod-web-agent",
        type: "ssh_key",
        owner: "infra-team",
        environment: "prod",
        secret_value: "secret123pass"
      }
    });

    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      alias: "ssh-prod-web-agent",
      type: "ssh_key",
      masked_value: "••••••••"
    });
    expect(JSON.stringify(result.structuredContent)).not.toContain("secret123pass");
  });

  it("permite registrar credenciales en SqliteControlPlane inMemory", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
      scopes: new Set(["secureit:credentials:write"]),
      controlPlane: new SqliteControlPlane({ inMemory: true })
    });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const result = await client.callTool({
      name: "secureit.credentials.add",
      arguments: {
        alias: "ssh-prod-web-sqlite-agent",
        type: "ssh_key",
        owner: "infra-team",
        environment: "prod",
        secret_value: "secret123sqlite"
      }
    });

    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      alias: "ssh-prod-web-sqlite-agent",
      type: "ssh_key",
      masked_value: "••••••••"
    });
    expect(JSON.stringify(result.structuredContent)).not.toContain("secret123sqlite");
  });

  it("permite registrar un servidor usando solo el campo name con valores por defecto automáticos", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
      scopes: new Set(["secureit:servers:write"]),
      controlPlane: new SqliteControlPlane({ inMemory: true })
    });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const result = await client.callTool({
      name: "secureit.servers.add",
      arguments: {
        name: "auto-server-01"
      }
    });

    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      state: "pending",
      admin_action_required: true
    });
  });

  it("registra credencial y pasa a estado managed si se provee usuario y contraseña en secureit.servers.add", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
      scopes: new Set(["secureit:servers:write"]),
      controlPlane: new SqliteControlPlane({ inMemory: true })
    });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const result = await client.callTool({
      name: "secureit.servers.add",
      arguments: {
        name: "direct-managed-01",
        username: "root",
        password: "SuperSecretPassword123"
      }
    });

    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      state: "managed",
      admin_action_required: false,
      next_step: "Servidor enrolado y listo para operar."
    });
    expect(result.structuredContent).toHaveProperty("credential_id");
  });

  it("permite registrar servidores con dominios de producción reales como api.aisolutionshub.ec", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
      scopes: new Set(["secureit:servers:write"]),
      controlPlane: new SqliteControlPlane({ inMemory: true })
    });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const result = await client.callTool({
      name: "secureit.servers.add",
      arguments: {
        name: "api.aisolutionshub.ec",
        username: "humberto",
        password: "MyPassword123"
      }
    });

    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      state: "managed",
      admin_action_required: false
    });
  });

  it("permite múltiples registros consecutivos sin idempotency_key sin causar conflicto de clave vacía", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
      scopes: new Set(["secureit:servers:write"]),
      controlPlane: new SqliteControlPlane({ inMemory: true })
    });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    const res1 = await client.callTool({
      name: "secureit.servers.add",
      arguments: { name: "server-alpha.example" }
    });
    expect(res1.isError).not.toBe(true);

    const res2 = await client.callTool({
      name: "secureit.servers.add",
      arguments: { name: "server-beta.example" }
    });
    expect(res2.isError).not.toBe(true);
  });

  it("reutiliza credenciales y servidores preexistentes sin lanzar error CONFLICT", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
      scopes: new Set(["secureit:servers:write", "secureit:credentials:write"]),
      controlPlane: new SqliteControlPlane({ inMemory: true })
    });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    // Register credential first
    await client.callTool({
      name: "secureit.credentials.add",
      arguments: { alias: "api.aisolutionshub.ec:humberto", secret_value: "Rc2020.2" }
    });

    // Call addServer with same alias / name
    const result = await client.callTool({
      name: "secureit.servers.add",
      arguments: {
        name: "api.aisolutionshub.ec",
        username: "humberto",
        password: "Rc2020.2"
      }
    });

    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({
      state: "managed",
      admin_action_required: false
    });
  });

  it("ejecuta comandos estándar como ls directamente sin requerir aprobación humana previa y retorna la salida", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
      scopes: new Set(["secureit:servers:write", "secureit:ssh:command"]),
      controlPlane: new SqliteControlPlane({ inMemory: true })
    });
    const client = new Client({ name: "integration-test", version: "1.0.0" });
    closeables.push(client, server);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    // Add server first
    await client.callTool({
      name: "secureit.servers.add",
      arguments: { name: "exec-server.example", username: "root", password: "SecretPassword123" }
    });

    // Execute ls
    const execRes = await client.callTool({
      name: "secureit.ssh.execute_command",
      arguments: { script: "ls -la" }
    });

    expect(execRes.isError).not.toBe(true);
    expect(execRes.structuredContent).toMatchObject({
      status: "completed",
      risk: "low"
    });
    expect(execRes.structuredContent).toHaveProperty("results");
  });
});
