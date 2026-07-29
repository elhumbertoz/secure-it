import type { Server as NodeHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { DemoControlPlane } from "@secure-it/control-plane";
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type CryptoKey
} from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { OidcJwtVerifier } from "../../apps/mcp/src/auth.js";
import type { HttpServerConfig } from "../../apps/mcp/src/config.js";
import { createHttpMcpApp } from "../../apps/mcp/src/http.js";
import type { ControlPlane } from "../../apps/mcp/src/server.js";

const issuer = "https://identity.example";
const audience = "https://secure-it.example/mcp";
const tokenMarker = "SYNTHETIC_HTTP_TOKEN_MARKER";

let privateKey: CryptoKey;
let verifier: OidcJwtVerifier;
const closeables: Array<{ close(): void | Promise<void> }> = [];

beforeAll(async () => {
  const keyPair = await generateKeyPair("RS256");
  privateKey = keyPair.privateKey;
  const publicJwk = await exportJWK(keyPair.publicKey);
  publicJwk.kid = "synthetic-test-key";
  verifier = new OidcJwtVerifier(
    { issuer, audience, jwksUri: "https://identity.example/jwks" },
    createLocalJWKSet({ keys: [publicJwk] })
  );
});

afterEach(async () => {
  await Promise.all(closeables.splice(0).map(async (value) => await value.close()));
});

describe("MCP remoto por Streamable HTTP", () => {
  it("expone salud, readiness y metadata sin revelar configuración", async () => {
    const baseUrl = await startServer();
    const health = await fetch(`${baseUrl}/healthz`);
    const ready = await fetch(`${baseUrl}/readyz`);
    const metadata = await fetch(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);

    expect(await health.json()).toEqual({ status: "ok" });
    expect(await ready.json()).toEqual({ status: "ready" });
    expect(JSON.stringify(await metadata.json())).not.toContain("jwks");
  });

  it("rechaza un token emitido para otra audiencia", async () => {
    const baseUrl = await startServer();
    const token = await issueToken({ audience: "https://other-mcp.example/mcp" });
    const response = await postInitialize(baseUrl, token);

    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain("invalid_token");
    expect(await response.text()).not.toContain(token);
  });

  it("rechaza peticiones MCP sin bearer token", async () => {
    const baseUrl = await startServer();
    const response = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json"
      },
      body: "{}"
    });

    expect(response.status).toBe(401);
  });

  it("rechaza por defecto un token sin scopes conocidos", async () => {
    const baseUrl = await startServer();
    const token = await issueToken({ scopes: [] });
    const response = await postInitialize(baseUrl, token);

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "insufficient_scope" });
  });

  it("rechaza tokens vencidos", async () => {
    const baseUrl = await startServer();
    const token = await issueToken({ expiresAt: Math.floor(Date.now() / 1000) - 60 });
    const response = await postInitialize(baseUrl, token);

    expect(response.status).toBe(401);
  });

  it("rechaza un Origin no permitido", async () => {
    const baseUrl = await startServer();
    const token = await issueToken({ scopes: ["secureit:servers:read"] });
    const response = await postInitialize(baseUrl, token, {
      Origin: "https://attacker.example"
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "origin_not_allowed" });
  });

  it("permite preflight únicamente para un Origin autorizado", async () => {
    const baseUrl = await startServer();
    const allowed = await fetch(`${baseUrl}/mcp`, {
      method: "OPTIONS",
      headers: { Origin: "https://client.example" }
    });
    const denied = await fetch(`${baseUrl}/mcp`, {
      method: "OPTIONS",
      headers: { Origin: "https://attacker.example" }
    });

    expect(allowed.status).toBe(204);
    expect(allowed.headers.get("access-control-allow-origin")).toBe("https://client.example");
    expect(denied.status).toBe(403);
  });

  it("filtra herramientas por scope y no reenvía el bearer token al dominio", async () => {
    const recorder = new RecordingControlPlane();
    const baseUrl = await startServer({}, recorder);
    const token = await issueToken({
      scopes: ["secureit:servers:read"],
      marker: tokenMarker
    });
    const client = await connectClient(baseUrl, token);

    const listed = await client.listTools();
    expect(listed.tools.map((tool) => tool.name).sort()).toEqual([
      "secureit.access_profiles.list",
      "secureit.servers.enrollment_status",
      "secureit.servers.get",
      "secureit.servers.list"
    ]);
    const result = await client.callTool({ name: "secureit.servers.list", arguments: {} });
    expect(result.isError).not.toBe(true);
    expect(recorder.calls).toHaveLength(1);
    expect(recorder.calls[0]?.context.subject).toBe("http-test-subject");
    expect(JSON.stringify(recorder.calls)).not.toContain(token);
    expect(JSON.stringify(recorder.calls)).not.toContain(tokenMarker);
  });

  it("deniega herramientas no visibles e intentos de administración desde MCP", async () => {
    const recorder = new RecordingControlPlane();
    const baseUrl = await startServer({}, recorder);
    const token = await issueToken({ scopes: ["secureit:servers:read"] });
    const client = await connectClient(baseUrl, token);

    const hidden = await client.callTool({
      name: "secureit.credentials.rotate",
      arguments: {}
    });
    const administrative = await client.callTool({
      name: "secureit.credentials.get",
      arguments: {}
    });
    const adminRoute = await fetch(`${baseUrl}/admin/credentials`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    expect(hidden.isError).toBe(true);
    expect(administrative.isError).toBe(true);
    expect(recorder.calls).toHaveLength(0);
    expect(adminRoute.status).toBe(404);
  });

  it("limita el tamaño de petición antes de ejecutar MCP", async () => {
    const baseUrl = await startServer({ requestMaxBytes: 1_024 });
    const token = await issueToken({ scopes: ["secureit:servers:read"] });
    const response = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ oversized: "x".repeat(2_000) })
    });

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: "request_too_large" });
  });

  it("rechaza un Content-Type que podría eludir el parser limitado", async () => {
    const baseUrl = await startServer({ requestMaxBytes: 1_024 });
    const token = await issueToken({ scopes: ["secureit:servers:read"] });
    const response = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "text/plain"
      },
      body: "x".repeat(2_000)
    });

    expect(response.status).toBe(415);
    expect(await response.json()).toEqual({ error: "unsupported_media_type" });
  });

  it("aplica rate limiting básico al endpoint MCP", async () => {
    const baseUrl = await startServer({ rateLimitMax: 1 });
    const token = await issueToken({ scopes: ["secureit:servers:read"] });
    const first = await postInitialize(baseUrl, token);
    const second = await postInitialize(baseUrl, token);

    expect(first.status).toBe(200);
    expect(second.status).toBe(429);
  });
});

class RecordingControlPlane implements ControlPlane {
  readonly calls: Array<{
    toolName: string;
    rawInput: unknown;
    context: { subject: string; scopes: ReadonlySet<string> };
  }> = [];
  private readonly delegate = new DemoControlPlane();

  async call(
    toolName: string,
    rawInput: unknown,
    context: { subject: string; scopes: ReadonlySet<string> }
  ): Promise<Record<string, unknown>> {
    this.calls.push({ toolName, rawInput, context });
    return await this.delegate.call(toolName, rawInput, context);
  }
}

async function startServer(
  overrides: Partial<HttpServerConfig> = {},
  controlPlane?: ControlPlane
): Promise<string> {
  const config: HttpServerConfig = {
    host: "127.0.0.1",
    port: 3000,
    publicUrl: new URL(audience),
    allowedHosts: ["127.0.0.1"],
    allowedOrigins: ["https://client.example"],
    requestMaxBytes: 65_536,
    rateLimitWindowMs: 60_000,
    rateLimitMax: 100,
    oidc: { issuer, audience, jwksUri: "https://identity.example/jwks" },
    authorizationUrl: new URL("https://identity.example/authorize"),
    tokenUrl: new URL("https://identity.example/token"),
    ...overrides
  };
  const app = createHttpMcpApp({
    config,
    verifier,
    ...(controlPlane ? { controlPlane } : {})
  });
  const server = await new Promise<NodeHttpServer>((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  closeables.push({
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${String(address.port)}`;
}

async function connectClient(baseUrl: string, token: string): Promise<Client> {
  const client = new Client({ name: "http-integration-test", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  });
  closeables.unshift(client);
  await client.connect(transport);
  return client;
}

async function issueToken(options: {
  audience?: string;
  scopes?: string[];
  expiresAt?: number;
  marker?: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const token = new SignJWT({
    client_id: "synthetic-client",
    ...(options.scopes ? { scope: options.scopes.join(" ") } : {}),
    ...(options.marker ? { marker: options.marker } : {})
  })
    .setProtectedHeader({ alg: "RS256", kid: "synthetic-test-key" })
    .setIssuer(issuer)
    .setAudience(options.audience ?? audience)
    .setSubject("http-test-subject")
    .setIssuedAt(now)
    .setExpirationTime(options.expiresAt ?? now + 300);
  return await token.sign(privateKey);
}

async function postInitialize(
  baseUrl: string,
  token: string,
  extraHeaders: Record<string, string> = {}
): Promise<Response> {
  return await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
      ...extraHeaders
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "http-negative-test", version: "1.0.0" }
      }
    })
  });
}
