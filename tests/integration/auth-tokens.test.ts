import type { Server as NodeHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteControlPlane } from "@secure-it/control-plane";
import { createMcpServer } from "../../apps/mcp/src/server.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createAdminServer } from "../../apps/admin/src/server.js";
import { allDemoScopes } from "@secure-it/contracts";

const closeables: Array<{ close(): void | Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(closeables.splice(0).map(async (item) => await item.close()));
});

async function startAdmin(): Promise<{ baseUrl: string; token: string; controlPlane: SqliteControlPlane }> {
  const controlPlane = new SqliteControlPlane({ inMemory: true });
  const { app } = createAdminServer({ controlPlane });
  const server: NodeHttpServer = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  closeables.push({ close: () => new Promise<void>((res, rej) => server.close((e) => (e ? rej(e) : res()))) });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const login = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "admin" })
  });
  const body = await login.json() as { session_token: string };
  return { baseUrl: base, token: body.session_token, controlPlane };
}

async function mcpWithIdentity(controlPlane: SqliteControlPlane, tokenId?: string) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer({
    controlPlane,
    identity: {
      subject: tokenId ? `token:${tokenId.slice(0, 6)}` : "demo",
      scopes: new Set(allDemoScopes),
      ...(tokenId ? { tokenId } : {})
    }
  });
  const client = new Client({ name: "test", version: "1.0.0" });
  closeables.push(client, server);
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

describe("Administración: usuarios, tokens y aislamiento", () => {
  it("login válido devuelve sesión y el admin sehace listar servidores", async () => {
    const { baseUrl, token } = await startAdmin();
    expect(token).toMatch(/^ses_/);
    const res = await fetch(`${baseUrl}/api/servers`, { headers: { "X-Admin-Token": token } });
    expect(res.status).toBe(200);
    const data = await res.json() as { servers: unknown[] };
    expect(Array.isArray(data.servers)).toBe(true);
  });

  it("rechaza credenciales inválidas (401) y sesión inválida (401)", async () => {
    const { baseUrl } = await startAdmin();
    const bad = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "wrong" })
    });
    expect(bad.status).toBe(401);

    const noAuth = await fetch(`${baseUrl}/api/credentials`);
    expect(noAuth.status).toBe(401);
  });

  it("cambia la contraseña del admin y la nueva funciona", async () => {
    const { baseUrl, token } = await startAdmin();
    const res = await fetch(`${baseUrl}/api/auth/change-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Token": token },
      body: JSON.stringify({ current_password: "admin", new_password: "nuevaClave99" })
    });
    expect(res.status).toBe(200);

    // Login con la nueva contraseña.
    const login = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "nuevaClave99" })
    });
    expect(login.status).toBe(200);
  });

  it("emite un session-token y un admin puede listar tokens", async () => {
    const { baseUrl, token } = await startAdmin();
    const created = await fetch(`${baseUrl}/api/tokens`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Token": token },
      body: JSON.stringify({ name: "agent-cicd" })
    });
    const cdata = await created.json() as { raw_token: string };
    expect(cdata.raw_token).toMatch(/^sit_/);

    const list = await fetch(`${baseUrl}/api/tokens`, { headers: { "X-Admin-Token": token } });
    const ldata = await list.json() as { tokens: Array<{ name: string; is_general: boolean }> };
    expect(ldata.tokens.some((t) => t.name === "agent-cicd")).toBe(true);
    expect(ldata.tokens.some((t) => t.is_general === true)).toBe(true);
  });

  it("un servidor agregado con un token solo es visible para ese token (no para otros)", async () => {
    const { baseUrl, token, controlPlane } = await startAdmin();
    const ensureGeneral = controlPlane.ensureGeneralToken();
    const generalId = ensureGeneral.id;

    // Crea dos tokens diferentes.
    const t1 = await (await fetch(`${baseUrl}/api/tokens`, {
      method: "POST", headers: { "Content-Type": "application/json", "X-Admin-Token": token },
      body: JSON.stringify({ name: "alpha" })
    })).json() as { token: { id: string }; raw_token: string };
    void t1.raw_token;
    const t2 = await (await fetch(`${baseUrl}/api/tokens`, {
      method: "POST", headers: { "Content-Type": "application/json", "X-Admin-Token": token },
      body: JSON.stringify({ name: "beta" })
    })).json() as { token: { id: string } };

    const alphaId = t1.token.id;
    const betaId = t2.token.id;
    expect(alphaId).not.toBe(betaId);

    // alpha agrega un servidor.
    const clientAlpha = await mcpWithIdentity(controlPlane, alphaId);
    const addRes = await clientAlpha.callTool({
      name: "secureit.servers.add",
      arguments: { name: "iso-server-alpha", username: "root", password: "Secret123" }
    });
    expect(addRes.isError).not.toBe(true);

    // alpha puede listarlo.
    const listAlpha = await clientAlpha.callTool({ name: "secureit.servers.list", arguments: {} });
    const alphaServers = (listAlpha.structuredContent as { servers: { name: string }[] }).servers;
    expect(alphaServers.some((s) => s.name === "iso-server-alpha")).toBe(true);

    // beta NO puede verlo (asignado por el caller a alpha).
    const clientBeta = await mcpWithIdentity(controlPlane, betaId);
    const listBeta = await clientBeta.callTool({ name: "secureit.servers.list", arguments: {} });
    const betaServers = (listBeta.structuredContent as { servers: { name: string }[] }).servers;
    expect(betaServers.some((s) => s.name === "iso-server-alpha")).toBe(false);

    // beta tampoco puede obtenerlo directamente (POLICY_DENIED).
    const getSrv = await clientBeta.callTool({
      name: "secureit.servers.get",
      arguments: { server_id: (await controlPlane.listServersForAdmin()).find((s) => s.name === "iso-server-alpha")!.id }
    });
    expect(getSrv.isError).toBe(true);

    // El token general sigue sin ver el servidor de alpha (es dueño del general).
    const clientGeneral = await mcpWithIdentity(controlPlane, generalId);
    const listGeneral = await clientGeneral.callTool({ name: "secureit.servers.list", arguments: {} });
    const generalServers = (listGeneral.structuredContent as { servers: { name: string }[] }).servers;
    expect(generalServers.some((s) => s.name === "iso-server-alpha")).toBe(false);

    // Admin extiende el acceso de beta al servidor de alpha mediante grant.
    const sid = (await controlPlane.listServersForAdmin()).find((s) => s.name === "iso-server-alpha")!.id;
    const grantRes = await fetch(`${baseUrl}/api/servers/${sid}/grants`, {
      method: "POST", headers: { "Content-Type": "application/json", "X-Admin-Token": token },
      body: JSON.stringify({ token_id: betaId })
    });
    expect(grantRes.status).toBe(201);

    // Ahora beta sí lo ve.
    const listBeta2 = await clientBeta.callTool({ name: "secureit.servers.list", arguments: {} });
    const betaServers2 = (listBeta2.structuredContent as { servers: { name: string }[] }).servers;
    expect(betaServers2.some((s) => s.name === "iso-server-alpha")).toBe(true);
  });

  it("el token general de fallback posee los servidores que agrega", async () => {
    const { controlPlane } = await startAdmin();
    const general = controlPlane.ensureGeneralToken();
    const client = await mcpWithIdentity(controlPlane, general.id);
    const addRes = await client.callTool({
      name: "secureit.servers.add",
      arguments: { name: "general-owned-01", username: "root", password: "Secret123" }
    });
    expect(addRes.isError).not.toBe(true);
    const list = await client.callTool({ name: "secureit.servers.list", arguments: {} });
    const servers = (list.structuredContent as { servers: { name: string }[] }).servers;
    expect(servers.some((s) => s.name === "general-owned-01")).toBe(true);

    // Un token distinto no lo ve.
    const other = controlPlane.createToken("other");
    await controlPlane.grantServerAccess; // noop ref
    const clientOther = await mcpWithIdentity(controlPlane, other.token.id);
    const listOther = await clientOther.callTool({ name: "secureit.servers.list", arguments: {} });
    const otherServers = (listOther.structuredContent as { servers: { name: string }[] }).servers;
    expect(otherServers.some((s) => s.name === "general-owned-01")).toBe(false);
  });
});
