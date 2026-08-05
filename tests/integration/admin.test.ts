import type { Server as NodeHttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteControlPlane } from "@secure-it/control-plane";
import { createAdminServer } from "../../apps/admin/src/server.js";

const closeables: Array<{ close(): void | Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(closeables.splice(0).map(async (item) => await item.close()));
});

async function startAdminServer(): Promise<{ baseUrl: string; token: string; controlPlane: SqliteControlPlane }> {
  const controlPlane = new SqliteControlPlane({ inMemory: true, seedTestServer: true });
  const { app } = createAdminServer({ controlPlane });

  const server: NodeHttpServer = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });

  closeables.push({
    close() {
      return new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    }
  });

  const address = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  // Login con el usuario por defecto admin/admin (creado en el arranque).
  const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "admin" })
  });
  const loginBody = await loginRes.json() as { session_token: string };
  const token = loginBody.session_token;

  return { baseUrl, token, controlPlane };
}

describe("Interfaz Administrativa Web de Credenciales", () => {
  it("incluye cabeceras de seguridad estrictas (CSP, X-Frame-Options, X-Content-Type-Options)", async () => {
    const { baseUrl } = await startAdminServer();
    const res = await fetch(`${baseUrl}/api/health`);

    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
  });

  it("rechaza peticiones sin token admin (401 UNAUTHORIZED)", async () => {
    const { baseUrl } = await startAdminServer();
    const res = await fetch(`${baseUrl}/api/credentials`);

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe("UNAUTHORIZED");
  });

  it("RECHAZA explícitamente tokens o sesiones MCP (403 POLICY_DENIED)", async () => {
    const { baseUrl, token } = await startAdminServer();

    // Headers with MCP tokens must be denied
    const res = await fetch(`${baseUrl}/api/credentials`, {
      headers: {
        "X-Admin-Token": token,
        "X-MCP-Token": "some-mcp-agent-token"
      }
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("POLICY_DENIED");
    expect(body.message).toContain("MCP");
  });

  it("retorna lista de credenciales con secreto enmascarado y secretValue omitido", async () => {
    const { baseUrl, token } = await startAdminServer();

    const res = await fetch(`${baseUrl}/api/credentials`, {
      headers: { "X-Admin-Token": token }
    });

    expect(res.status).toBe(200);
    const list = await res.json();
    expect(Array.isArray(list)).toBe(true);
    expect(list.length).toBeGreaterThan(0);

    for (const cred of list) {
      expect(cred.secretValue).toBeUndefined();
      expect(cred.maskedValue).toBe("••••••••");
    }
  });

  it("permite importar una nueva credencial y genera evento de auditoría", async () => {
    const { baseUrl, token } = await startAdminServer();

    const importRes = await fetch(`${baseUrl}/api/credentials`, {
      method: "POST",
      headers: {
        "X-Admin-Token": token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        alias: "test-redis-password",
        type: "db_password",
        owner: "cache-team",
        environment: "staging",
        exportable: true,
        secretValue: "super_secret_redis_pass"
      })
    });

    expect(importRes.status).toBe(201);
    const created = await importRes.json();
    expect(created.alias).toBe("test-redis-password");
    expect(created.secretValue).toBeUndefined();

    // Verify audit event was logged
    const auditRes = await fetch(`${baseUrl}/api/audit-events`, {
      headers: { "X-Admin-Token": token }
    });
    const audits = await auditRes.json();
    const importAudit = audits.find((a: any) => a.operation === "credential:import" && a.objectIds.includes(created.id));
    expect(importAudit).toBeDefined();
    expect(importAudit.outcome).toBe("allowed");
  });

  it("permite revelar credencial exportable e inscribe evento de auditoría de revelado", async () => {
    const { baseUrl, token } = await startAdminServer();

    const listRes = await fetch(`${baseUrl}/api/credentials`, {
      headers: { "X-Admin-Token": token }
    });
    const list = await listRes.json();
    const exportableCred = list.find((c: any) => c.exportable === true);
    expect(exportableCred).toBeDefined();

    const revealRes = await fetch(`${baseUrl}/api/credentials/${exportableCred.id}/reveal`, {
      method: "POST",
      headers: {
        "X-Admin-Token": token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ reason: "Auditoría de integración de pruebas" })
    });

    expect(revealRes.status).toBe(200);
    const revealed = await revealRes.json();
    expect(typeof revealed.secretValue).toBe("string");
    expect(revealed.secretValue.length).toBeGreaterThan(0);

    // Verify reveal audit event
    const auditRes = await fetch(`${baseUrl}/api/audit-events`, {
      headers: { "X-Admin-Token": token }
    });
    const audits = await auditRes.json();
    const revealAudit = audits.find((a: any) => a.operation === "credential:reveal" && a.objectIds.includes(exportableCred.id));
    expect(revealAudit).toBeDefined();
    expect(revealAudit.reasonCode).toBe("Auditoría de integración de pruebas");
  });

  it("DENEGA revelado para credencial NO exportable (ca_private_key)", async () => {
    const { baseUrl, token } = await startAdminServer();

    const listRes = await fetch(`${baseUrl}/api/credentials`, {
      headers: { "X-Admin-Token": token }
    });
    const list = await listRes.json();
    const nonExportableCred = list.find((c: any) => c.exportable === false);
    expect(nonExportableCred).toBeDefined();

    const revealRes = await fetch(`${baseUrl}/api/credentials/${nonExportableCred.id}/reveal`, {
      method: "POST",
      headers: {
        "X-Admin-Token": token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ reason: "Intento no autorizado" })
    });

    expect(revealRes.status).toBe(403);
    const body = await revealRes.json();
    expect(body.error).toBe("POLICY_DENIED");

    // Verify denied audit event logged
    const auditRes = await fetch(`${baseUrl}/api/audit-events`, {
      headers: { "X-Admin-Token": token }
    });
    const audits = await auditRes.json();
    const deniedAudit = audits.find((a: any) => a.operation === "credential:reveal" && a.outcome === "denied" && a.objectIds.includes(nonExportableCred.id));
    expect(deniedAudit).toBeDefined();
  });

  it("ejecuta rotación y revocación correctamente", async () => {
    const { baseUrl, token } = await startAdminServer();

    const listRes = await fetch(`${baseUrl}/api/credentials`, {
      headers: { "X-Admin-Token": token }
    });
    const list = await listRes.json();
    const cred = list[0];

    // Rotate
    const rotateRes = await fetch(`${baseUrl}/api/credentials/${cred.id}/rotate`, {
      method: "POST",
      headers: { "X-Admin-Token": token }
    });
    expect(rotateRes.status).toBe(200);
    const rotated = await rotateRes.json();
    expect(rotated.version).toBe(cred.version + 1);

    // Test access
    const testRes = await fetch(`${baseUrl}/api/credentials/${cred.id}/test`, {
      method: "POST",
      headers: { "X-Admin-Token": token }
    });
    expect(testRes.status).toBe(200);

    // Revoke
    const revokeRes = await fetch(`${baseUrl}/api/credentials/${cred.id}/revoke`, {
      method: "POST",
      headers: { "X-Admin-Token": token }
    });
    expect(revokeRes.status).toBe(200);
    const revoked = await revokeRes.json();
    expect(revoked.status).toBe("revoked");
  });

  it("permite listar, registrar y eliminar servidores desde la API admin (/api/servers)", async () => {
    const { baseUrl, token } = await startAdminServer();

    // GET /api/servers
    const getRes = await fetch(`${baseUrl}/api/servers`, {
      headers: { "X-Admin-Token": token }
    });
    expect(getRes.status).toBe(200);
    const initialList = await getRes.json();
    expect(initialList).toHaveProperty("servers");

    // POST /api/servers
    const postRes = await fetch(`${baseUrl}/api/servers`, {
      method: "POST",
      headers: {
        "X-Admin-Token": token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name: "admin-created-server-01",
        username: "admin",
        password: "AdminPassword123"
      })
    });
    expect(postRes.status).toBe(201);
    const created = await postRes.json();
    expect(created.state).toBe("managed");

    // DELETE /api/servers/:id
    const delRes = await fetch(`${baseUrl}/api/servers/${created.server_id}`, {
      method: "DELETE",
      headers: { "X-Admin-Token": token }
    });
    expect(delRes.status).toBe(200);
  });
});
