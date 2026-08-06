export type Environment = "dev" | "test" | "staging" | "prod";
export type Criticality = "low" | "medium" | "high" | "critical";
export type LifecycleState = "pending" | "managed" | "quarantined" | "retired";
export type ConnectionMode = "local_agent" | "ssh_cert" | "cloud_api";

export interface ServerRecord {
  id: string;
  name: string;
  environment: Environment;
  owner: string;
  /**
   * Identificador del token interno (session-token / token general) que agregó
   * el servidor. Por defecto, solo ese token puede accederlo desde el MCP; el
   * admin puede extender el permiso a otros tokens mediante un `TokenServerGrant`.
   * `null` indica que el servidor no está vinculado a un token interno (p. ej.
   * agregado por una identidad OIDC externa o por el admin) y no se filtra por
   * propiedad de token.
   */
  ownerTokenId?: string | null;
  criticality: Criticality;
  lifecycleState: LifecycleState;
  connectionMode: ConnectionMode;
  labels: Record<string, string>;
  endpoint: { address: string; port: number };
  expectedHostIdentity: string;
  accessProfileId: string;
  /**
   * Alias de la credencial de login asociada al servidor (asignada en
   * `servers.add` cuando se aporta `username`/`password`). El ejecutor real lo
   * usa para resolver el secreto internamente; nunca se expone al agente.
   */
  credentialAlias?: string;
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
  /**
   * Plantilla de comando shell ejecutada por el ejecutor real (p. ej. SSH).
   * Marcadores de posición con `{nombre}` sustituidos por parámetros validados
   * por `parameterSchema`. Si se omite, la acción solo produce salida sintética.
   * El ejecutor NUNCA acepta plantillas desde el agente; provienen del catálogo
   * revisado y versionado.
   */
  commandTemplate?: string;
  /**
   * Si es true, el ejecutor antepone `sudo -n` (NOPASSWD-gated por sudoers del
   * remoto). Jamás se inyecta el password sudo al agente. Si el remoto no tiene
   * sudoers NOPASSWD para el binario, la acción falla con stderr legible.
   */
  elevatedPrivilege?: boolean;
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
  /** Token interno que agregó la credencial (proveniencia). No se enforce. */
  ownerTokenId?: string | null;
  environment: Environment;
  status: CredentialStatus;
  version: number;
  lastRotatedAt: string;
  expiresAt: string | null;
  exportable: boolean;
  maskedValue: string;
  /**
   * Secreto en claro. NUNCA se persiste: existe solo en memoria tras
   * descifrar `secretCipher` (o, para filas legacy sin cifrar, tras leer el
   * valor plano pendiente de migrar). Se elimina antes de toda exposición
   * externa (listados, respuestas MCP/admin).
   */
  secretValue?: string;
  /**
   * Secreto cifrado con AES-256-GCM que se persiste en la base de datos.
   * Formato: `v1.<base64(iv)>.<base64(tag)>.<base64(ciphertext)>`.
   */
  secretCipher?: string;
  /** Candidato cifrado previo a una rotación remota; nunca se expone en listados. */
  pendingSecretCipher?: string;
}

export interface RequestContext {
  subject: string;
  scopes: ReadonlySet<string>;
  /**
   * Identificador del token interno que identifica al llamante. Si está presente,
   * el plano de control aplica el aislamiento por propiedad de servidor. Si es
   * `undefined` (identidades externas OIDC o llamadas no tokenizadas) no se filtra
   * por propiedad, preservando el comportamiento demo.
   */
  tokenId?: string;
  /** `true` para la consola admin human: omite el aislamiento por token. */
  isAdmin?: boolean;
}

export interface AdminUser {
  id: string;
  username: string;
  passwordHash: string;
  createdAt: string;
}

export interface TokenRecord {
  id: string;
  /** SHA-256 del valor crudo del token (nunca se persiste el crudo). */
  tokenHash: string;
  name: string;
  /** Sujeto de identidad usado en auditoría/manifests. */
  subject: string;
  scopes: string[];
  isGeneral: boolean;
  active: boolean;
  createdAt: string;
  expiresAt: string | null;
}

export interface TokenServerGrant {
  tokenId: string;
  serverId: string;
  grantedBy: string;
  grantedAt: string;
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
