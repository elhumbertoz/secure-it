import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { unlinkSync, existsSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { SqliteControlPlane } from "../../packages/control-plane/src/sqlite-store.js";
import type { RequestContext } from "../../packages/control-plane/src/types.js";

const demoContext: RequestContext = {
  subject: "test-admin",
  scopes: new Set([
    "secureit:servers:read",
    "secureit:servers:write",
    "secureit:actions:read",
    "secureit:actions:execute",
    "secureit:jobs:read",
    "secureit:jobs:cancel",
    "secureit:credentials:rotate"
  ])
};

describe("SqliteControlPlane (Zero-DB persistence)", () => {
  it("inicializa el esquema sin servidores de ejemplo por defecto", async () => {
    const cp = new SqliteControlPlane({ inMemory: true });
    const serversResult = await cp.call("secureit.servers.list", {}, demoContext);
    expect(serversResult).toHaveProperty("servers");
    const servers = serversResult.servers as unknown[];
    expect(servers.length).toBe(0);
    cp.close();
  });

  it("persiste cambios entre instancias en el archivo sqlite local", async () => {
    const dbPath = join(tmpdir(), `test-secureit-${randomUUID()}.db`);
    try {
      // Instancia 1: Añadir servidor
      const cp1 = new SqliteControlPlane({ dbPath });
      const addResult = await cp1.call(
        "secureit.servers.add",
        {
          name: "test-persistent-server-01",
          environment: "dev",
          owner: "dev-team",
          criticality: "low",
          connection_mode: "local_agent",
          management_endpoint: { address: "203.0.113.50", port: 8443 },
          expected_host_identity: "SHA256:TEST000000000000000000000000000000000000001",
          access_profile_id: "10000000-0000-4000-8000-000000000001",
          reason: "Test persistence",
          idempotency_key: "40000000-0000-4000-8000-000000000099"
        },
        demoContext
      );
      expect(addResult).toHaveProperty("server_id");
      const serverId = addResult.server_id as string;
      cp1.close();

      // Instancia 2: Leer el servidor creado previamente desde la misma base de datos
      const cp2 = new SqliteControlPlane({ dbPath });
      const getResult = await cp2.call("secureit.servers.get", { server_id: serverId }, demoContext);
      expect(getResult).toMatchObject({
        server_id: serverId,
        name: "test-persistent-server-01",
        environment: "dev"
      });
      cp2.close();

      // Instancia 3: Eliminar el servidor y comprobar persistencia de la eliminación
      const cp3 = new SqliteControlPlane({ dbPath });
      const removeResult = await cp3.call(
        "secureit.servers.remove",
        {
          server_id: serverId,
          reason: "Eliminar servidor en test de integración",
          idempotency_key: "40000000-0000-4000-8000-000000000098"
        },
        demoContext
      );
      expect(removeResult).toHaveProperty("removed", true);

      await expect(
        cp3.call("secureit.servers.get", { server_id: serverId }, demoContext)
      ).rejects.toThrow();
      cp3.close();
    } finally {
      if (existsSync(dbPath)) {
        unlinkSync(dbPath);
      }
    }
  });
});
