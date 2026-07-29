import { describe, expect, it } from "vitest";
import {
  allDemoScopes,
  toolCatalog,
  validateToolInput,
  validateToolOutput
} from "@secure-it/contracts";
import { DemoControlPlane } from "@secure-it/control-plane";

const context = { subject: "contract-test", scopes: new Set(allDemoScopes) };
const serverId = "20000000-0000-4000-8000-000000000001";
const profileId = "10000000-0000-4000-8000-000000000001";

describe("catálogo MCP", () => {
  it("mantiene un scope para cada herramienta publicada", () => {
    expect(toolCatalog.tools).toHaveLength(14);
    expect(new Set(toolCatalog.tools.map((tool) => tool.name)).size).toBe(toolCatalog.tools.length);
  });

  it("ejecuta la vertical demo y valida cada salida producida", async () => {
    const plane = new DemoControlPlane({ seedTestServer: true });

    const list = await plane.call("secureit.servers.list", {}, context);
    validateToolOutput("secureit.servers.list", list);

    const cred = await plane.call(
      "secureit.credentials.add",
      {
        alias: "demo-cred-01",
        type: "ssh_key",
        owner: "platform-team",
        environment: "test",
        secret_value: "my-secret-key-123"
      },
      context
    );
    validateToolOutput("secureit.credentials.add", cred);
    expect(cred).not.toHaveProperty("secret_value");

    const get = await plane.call("secureit.servers.get", { server_id: serverId }, context);
    validateToolOutput("secureit.servers.get", get);
    expect(get).not.toHaveProperty("endpoint");
    expect(get).not.toHaveProperty("access_profile_id");

    const profiles = await plane.call("secureit.access_profiles.list", {}, context);
    validateToolOutput("secureit.access_profiles.list", profiles);

    const addInput = {
      name: "new-demo-01.example",
      environment: "test",
      owner: "platform-demo",
      criticality: "low",
      connection_mode: "local_agent",
      management_endpoint: { address: "203.0.113.50", port: 443 },
      expected_host_identity: "SHA256:DEMO000000000000000000000000000000000000099",
      access_profile_id: profileId,
      reason: "Validar el alta de contrato",
      idempotency_key: "40000000-0000-4000-8000-000000000001"
    };
    const added = await plane.call("secureit.servers.add", addInput, context);
    validateToolOutput("secureit.servers.add", added);

    const enrollment = await plane.call(
      "secureit.servers.enrollment_status",
      { server_id: added.server_id },
      context
    );
    validateToolOutput("secureit.servers.enrollment_status", enrollment);

    const actions = await plane.call("secureit.actions.list", { environment: "test" }, context);
    validateToolOutput("secureit.actions.list", actions);

    const executed = await plane.call(
      "secureit.ssh.execute_action",
      {
        action_id: "os.disk_usage",
        action_version: 1,
        server_ids: [serverId],
        parameters: { mountpoint: "/var" },
        reason: "Revisar capacidad del volumen",
        idempotency_key: "40000000-0000-4000-8000-000000000002"
      },
      context
    );
    validateToolOutput("secureit.ssh.execute_action", executed);

    const job = await plane.call(
      "secureit.jobs.get",
      { job_id: executed.job_id, include_output: true },
      context
    );
    validateToolOutput("secureit.jobs.get", job);

    const blind = await plane.call(
      "secureit.ssh.execute_command",
      {
        server_ids: [serverId],
        interpreter: "posix-sh",
        script: "uname -a",
        timeout_seconds: 10,
        reason: "Diagnóstico excepcional controlado",
        idempotency_key: "40000000-0000-4000-8000-000000000003"
      },
      context
    );
    validateToolOutput("secureit.ssh.execute_command", blind);
    expect(blind.status).toBe("awaiting_approval");

    const cancelled = await plane.call(
      "secureit.jobs.cancel",
      {
        job_id: blind.job_id,
        reason: "Cancelar diagnóstico de prueba",
        idempotency_key: "40000000-0000-4000-8000-000000000004"
      },
      context
    );
    validateToolOutput("secureit.jobs.cancel", cancelled);

    const rotation = await plane.call(
      "secureit.credentials.rotate",
      {
        server_ids: [serverId],
        access_profile_id: profileId,
        reason: "Ensayar rotación ciega controlada",
        idempotency_key: "40000000-0000-4000-8000-000000000005"
      },
      context
    );
    validateToolOutput("secureit.credentials.rotate", rotation);
    expect(rotation).not.toHaveProperty("secret");

    const removed = await plane.call(
      "secureit.servers.remove",
      {
        server_id: added.server_id,
        reason: "Eliminación de prueba de servidor recién creado",
        idempotency_key: "40000000-0000-4000-8000-000000000006"
      },
      context
    );
    validateToolOutput("secureit.servers.remove", removed);
    expect(removed.removed).toBe(true);
  });

  it("rechaza propiedades no declaradas", () => {
    expect(() =>
      validateToolInput("secureit.servers.get", {
        server_id: serverId,
        password: "synthetic-forbidden-value"
      })
    ).toThrow(/contrato/);
  });
});
