import type { AccessProfile, ActionDefinition, ServerRecord } from "./types.js";

export const demoProfiles: AccessProfile[] = [
  {
    id: "10000000-0000-4000-8000-000000000001",
    name: "linux-readonly-local-agent",
    connectionMode: "local_agent",
    environments: ["dev", "test", "staging", "prod"],
    maxTtlSeconds: 300
  },
  {
    id: "10000000-0000-4000-8000-000000000002",
    name: "linux-readonly-ssh-ca",
    connectionMode: "ssh_cert",
    environments: ["dev", "test", "staging", "prod"],
    maxTtlSeconds: 300
  }
];

export const demoServers: ServerRecord[] = [];

export const testServerRecord: ServerRecord = {
  id: "20000000-0000-4000-8000-000000000001",
  name: "web-test-01.example",
  environment: "test",
  owner: "platform-demo",
  criticality: "low",
  lifecycleState: "managed",
  connectionMode: "local_agent",
  labels: { role: "web", region: "example-west" },
  endpoint: { address: "192.0.2.10", port: 443 },
  expectedHostIdentity: "SHA256:DEMO000000000000000000000000000000000000001",
  accessProfileId: demoProfiles[0]!.id,
  bindingReady: true,
  identityReady: true
};

export const demoActions: ActionDefinition[] = [
  {
    id: "os.disk_usage",
    version: 1,
    description: "Consulta sintética del uso de un punto de montaje.",
    risk: "read",
    environments: ["dev", "test"],
    parameterSchema: {
      type: "object",
      additionalProperties: false,
      required: ["mountpoint"],
      properties: { mountpoint: { type: "string", enum: ["/", "/var", "/srv"] } }
    },
    maxTargets: 20
  },
  {
    id: "os.service_status",
    version: 1,
    description: "Consulta sintética del estado de un servicio permitido.",
    risk: "read",
    environments: ["dev", "test"],
    parameterSchema: {
      type: "object",
      additionalProperties: false,
      required: ["service"],
      properties: { service: { type: "string", enum: ["nginx", "postgresql", "sshd"] } }
    },
    maxTargets: 20
  }
];
