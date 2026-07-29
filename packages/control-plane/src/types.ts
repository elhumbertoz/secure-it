export type Environment = "dev" | "test" | "staging" | "prod";
export type Criticality = "low" | "medium" | "high" | "critical";
export type LifecycleState = "pending" | "managed" | "quarantined" | "retired";
export type ConnectionMode = "local_agent" | "ssh_cert" | "cloud_api";

export interface ServerRecord {
  id: string;
  name: string;
  environment: Environment;
  owner: string;
  criticality: Criticality;
  lifecycleState: LifecycleState;
  connectionMode: ConnectionMode;
  labels: Record<string, string>;
  endpoint: { address: string; port: number };
  expectedHostIdentity: string;
  accessProfileId: string;
  bindingReady: boolean;
  identityReady: boolean;
}

export interface AccessProfile {
  id: string;
  name: string;
  connectionMode: ConnectionMode;
  environments: Environment[];
  maxTtlSeconds: number;
}

export interface ActionDefinition {
  id: string;
  version: number;
  description: string;
  risk: "read" | "low" | "high" | "critical";
  environments: Environment[];
  parameterSchema: Record<string, unknown>;
  maxTargets: number;
}

export interface JobRecord {
  id: string;
  status: "awaiting_approval" | "queued" | "running" | "completed" | "failed" | "cancelled" | "expired";
  createdAt: string;
  expiresAt: string;
  results: Array<{
    serverId: string;
    serverAlias: string;
    status: string;
    exitCode: number | null;
    stdoutExcerpt: string | null;
    stderrExcerpt: string | null;
    truncated: boolean;
    secretDetected: boolean;
  }>;
}

export type CredentialType = "ssh_key" | "api_token" | "db_password" | "ca_private_key" | "tpm_identity";
export type CredentialStatus = "active" | "rotated" | "revoked" | "expired";

export interface CredentialRecord {
  id: string;
  alias: string;
  type: CredentialType;
  owner: string;
  environment: Environment;
  status: CredentialStatus;
  version: number;
  lastRotatedAt: string;
  expiresAt: string | null;
  exportable: boolean;
  maskedValue: string;
  secretValue?: string;
}

export interface RequestContext {
  subject: string;
  scopes: ReadonlySet<string>;
}

export interface AuditEvent {
  id: string;
  occurredAt: string;
  subject: string;
  operation: string;
  outcome: "allowed" | "denied";
  objectIds: string[];
  reasonCode: string;
}

