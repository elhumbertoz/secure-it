import { describe, expect, it } from "vitest";
import { allDemoScopes } from "@secure-it/contracts";
import {
  DemoControlPlane,
  DomainError,
  assertSafeDemoEndpoint,
  sanitizeOutput,
  sha256
} from "@secure-it/control-plane";

const serverId = "20000000-0000-4000-8000-000000000001";
const fullContext = { subject: "security-test", scopes: new Set(allDemoScopes) };

describe("controles del plano de control", () => {
  it("deniega endpoints internos, loopback y metadata cloud", () => {
    for (const address of ["127.0.0.1", "169.254.169.254", "10.0.0.5", "metadata.google.internal"]) {
      expect(() => assertSafeDemoEndpoint(address, 443)).toThrow(DomainError);
    }
    expect(() => assertSafeDemoEndpoint("host.example", 443)).not.toThrow();
    expect(() => assertSafeDemoEndpoint("192.0.2.42", 22)).not.toThrow();
  });

  it("filtra material con apariencia de secreto", () => {
    const result = sanitizeOutput("password=synthetic-canary-value", 65_536);
    expect(result).toEqual({ excerpt: null, truncated: false, secretDetected: true });
  });

  it("calcula hashes canónicos sin depender del orden de las claves", () => {
    expect(sha256({ b: 2, a: 1 })).toBe(sha256({ a: 1, b: 2 }));
  });

  it("aplica scopes en el dominio, no solo en tools/list", async () => {
    const plane = new DemoControlPlane();
    await expect(
      plane.call(
        "secureit.ssh.execute_action",
        {
          action_id: "os.disk_usage",
          action_version: 1,
          server_ids: [serverId],
          parameters: { mountpoint: "/" },
          reason: "Intento sin alcance suficiente",
          idempotency_key: "50000000-0000-4000-8000-000000000001"
        },
        { subject: "reader", scopes: new Set(["secureit:servers:read"]) }
      )
    ).rejects.toMatchObject({ code: "POLICY_DENIED" });
  });

  it("repite una respuesta idempotente y rechaza reutilización conflictiva", async () => {
    const plane = new DemoControlPlane();
    const input = {
      action_id: "os.disk_usage",
      action_version: 1,
      server_ids: [serverId],
      parameters: { mountpoint: "/" },
      reason: "Comprobar idempotencia segura",
      idempotency_key: "50000000-0000-4000-8000-000000000002"
    };
    const first = await plane.call("secureit.ssh.execute_action", input, fullContext);
    const repeated = await plane.call("secureit.ssh.execute_action", input, fullContext);
    expect(repeated).toEqual(first);

    await expect(
      plane.call(
        "secureit.ssh.execute_action",
        { ...input, reason: "Otra intención con la misma clave" },
        fullContext
      )
    ).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("no conserva scripts ciegos en auditoría", async () => {
    const plane = new DemoControlPlane();
    const marker = "SYNTHETIC_SCRIPT_MARKER_DO_NOT_STORE";
    await plane.call(
      "secureit.ssh.execute_command",
      {
        server_ids: [serverId],
        interpreter: "posix-sh",
        script: `printf ${marker}`,
        timeout_seconds: 10,
        reason: "Comprobar minimización de auditoría",
        idempotency_key: "50000000-0000-4000-8000-000000000003"
      },
      fullContext
    );
    expect(JSON.stringify(plane.getAuditEvents())).not.toContain(marker);
  });
});
