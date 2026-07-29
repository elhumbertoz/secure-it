import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { mkdirSync, existsSync } from "node:fs";
import {
  requiredScopeFor,
  validateJsonSchema,
  validateToolInput,
  validateToolOutput,
  type JsonObject
} from "@secure-it/contracts";
import { DomainError } from "./errors.js";
import { demoActions, demoProfiles, demoServers } from "./fixtures.js";
import { assertSafeDemoEndpoint, sanitizeOutput, sha256 } from "./security.js";
import type {
  AccessProfile,
  ActionDefinition,
  AuditEvent,
  Environment,
  JobRecord,
  RequestContext,
  ServerRecord
} from "./types.js";

const asString = (value: unknown): string => value as string;
const asStringArray = (value: unknown): string[] => value as string[];

export interface SqliteControlPlaneOptions {
  dbPath?: string;
  inMemory?: boolean;
}

export class SqliteControlPlane {
  private db: DatabaseSync;

  constructor(options: SqliteControlPlaneOptions = {}) {
    let dbPath = options.dbPath;
    if (options.inMemory) {
      dbPath = ":memory:";
    } else if (!dbPath) {
      const defaultDir = join(homedir(), ".secure-it");
      if (!existsSync(defaultDir)) {
        mkdirSync(defaultDir, { recursive: true });
      }
      dbPath = join(defaultDir, "secureit.db");
    }

    this.db = new DatabaseSync(dbPath);
    this.initSchema();
    this.seedIfEmpty();
  }

  close(): void {
    this.db.close();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS profiles (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS actions (
        id_version TEXT PRIMARY KEY,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS idempotency (
        compound_key TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL,
        response TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        occurred_at TEXT NOT NULL,
        data TEXT NOT NULL
      );
    `);
  }

  private seedIfEmpty(): void {
    const row = this.db.prepare("SELECT COUNT(*) as count FROM servers").get() as { count: number };
    if (row && row.count > 0) return;

    const insertServer = this.db.prepare("INSERT INTO servers (id, name, data) VALUES (?, ?, ?)");
    for (const server of demoServers) {
      insertServer.run(server.id, server.name, JSON.stringify(server));
    }

    const insertProfile = this.db.prepare("INSERT INTO profiles (id, name, data) VALUES (?, ?, ?)");
    for (const profile of demoProfiles) {
      insertProfile.run(profile.id, profile.name, JSON.stringify(profile));
    }

    const insertAction = this.db.prepare("INSERT INTO actions (id_version, data) VALUES (?, ?)");
    for (const action of demoActions) {
      insertAction.run(`${action.id}@${action.version}`, JSON.stringify(action));
    }
  }

  async call(toolName: string, rawInput: unknown, context: RequestContext): Promise<JsonObject> {
    try {
      this.authorize(toolName, context);
      validateToolInput(toolName, rawInput);
      const output = await this.dispatch(toolName, rawInput as JsonObject, context);
      validateToolOutput(toolName, output);
      this.audit(context, toolName, "allowed", this.objectIds(rawInput), "OK");
      return output;
    } catch (error) {
      const reasonCode = error instanceof DomainError ? error.code : "INVALID_ARGUMENT";
      this.audit(context, toolName, "denied", this.objectIds(rawInput), reasonCode);
      throw error;
    }
  }

  getAuditEvents(): readonly AuditEvent[] {
    const rows = this.db.prepare("SELECT data FROM audit_events ORDER BY occurred_at ASC").all() as { data: string }[];
    return rows.map((r) => JSON.parse(r.data) as AuditEvent);
  }

  private authorize(toolName: string, context: RequestContext): void {
    if (!context.subject) throw new DomainError("POLICY_DENIED", "Falta una identidad autenticada");
    const requiredScope = requiredScopeFor(toolName);
    if (!context.scopes.has(requiredScope)) {
      throw new DomainError("POLICY_DENIED", "La identidad no tiene el alcance requerido");
    }
  }

  private async dispatch(toolName: string, input: JsonObject, context: RequestContext): Promise<JsonObject> {
    switch (toolName) {
      case "secureit.servers.list":
        return this.listServers(input);
      case "secureit.servers.get":
        return this.getServer(input);
      case "secureit.access_profiles.list":
        return this.listProfiles(input);
      case "secureit.servers.add":
        return this.addServer(input, context);
      case "secureit.servers.enrollment_status":
        return this.enrollmentStatus(input);
      case "secureit.servers.verify":
        return this.verifyServer(input, context);
      case "secureit.actions.list":
        return this.listActions(input);
      case "secureit.ssh.execute_action":
        return this.executeAction(input, context);
      case "secureit.ssh.execute_command":
        return this.executeCommand(input, context);
      case "secureit.jobs.get":
        return this.getJob(input);
      case "secureit.jobs.cancel":
        return this.cancelJob(input, context);
      case "secureit.credentials.rotate":
        return this.rotateCredential(input, context);
      default:
        throw new DomainError("NOT_FOUND", "La herramienta solicitada no existe");
    }
  }

  private getAllServers(): ServerRecord[] {
    const rows = this.db.prepare("SELECT data FROM servers").all() as { data: string }[];
    return rows.map((r) => JSON.parse(r.data) as ServerRecord);
  }

  private getServerById(id: string): ServerRecord | null {
    const row = this.db.prepare("SELECT data FROM servers WHERE id = ?").get(id) as { data: string } | undefined;
    return row ? (JSON.parse(row.data) as ServerRecord) : null;
  }

  private requireServer(id: string): ServerRecord {
    const server = this.getServerById(id);
    if (!server) throw new DomainError("NOT_FOUND", "El servidor no existe o no es visible");
    return server;
  }

  private saveServer(server: ServerRecord): void {
    this.db
      .prepare("INSERT OR REPLACE INTO servers (id, name, data) VALUES (?, ?, ?)")
      .run(server.id, server.name, JSON.stringify(server));
  }

  private getAllProfiles(): AccessProfile[] {
    const rows = this.db.prepare("SELECT data FROM profiles").all() as { data: string }[];
    return rows.map((r) => JSON.parse(r.data) as AccessProfile);
  }

  private getProfileById(id: string): AccessProfile | null {
    const row = this.db.prepare("SELECT data FROM profiles WHERE id = ?").get(id) as { data: string } | undefined;
    return row ? (JSON.parse(row.data) as AccessProfile) : null;
  }

  private requireProfile(id: string): AccessProfile {
    const profile = this.getProfileById(id);
    if (!profile) throw new DomainError("NOT_FOUND", "El perfil de acceso no existe o no es visible");
    return profile;
  }

  private getAllActions(): ActionDefinition[] {
    const rows = this.db.prepare("SELECT data FROM actions").all() as { data: string }[];
    return rows.map((r) => JSON.parse(r.data) as ActionDefinition);
  }

  private getActionByIdVersion(id: string, version: number): ActionDefinition | null {
    const row = this.db.prepare("SELECT data FROM actions WHERE id_version = ?").get(`${id}@${version}`) as
      | { data: string }
      | undefined;
    return row ? (JSON.parse(row.data) as ActionDefinition) : null;
  }

  private saveJob(job: JobRecord): void {
    this.db
      .prepare("INSERT OR REPLACE INTO jobs (id, status, data) VALUES (?, ?, ?)")
      .run(job.id, job.status, JSON.stringify(job));
  }

  private getJobById(id: string): JobRecord | null {
    const row = this.db.prepare("SELECT data FROM jobs WHERE id = ?").get(id) as { data: string } | undefined;
    return row ? (JSON.parse(row.data) as JobRecord) : null;
  }

  private listServers(input: JsonObject): JsonObject {
    const limit = (input.limit as number | undefined) ?? 50;
    const offset = this.decodeCursor(input.cursor as string | undefined);
    const labelFilter = input.label as string | undefined;

    const filtered = this.getAllServers()
      .filter((server) => !input.environment || server.environment === input.environment)
      .filter((server) => !input.state || server.lifecycleState === input.state)
      .filter((server) => !labelFilter || this.hasLabel(server.labels, labelFilter))
      .sort((left, right) => left.name.localeCompare(right.name));

    const page = filtered.slice(offset, offset + limit);
    const hasMore = offset + page.length < filtered.length;
    const result: JsonObject = {
      servers: page.map((server) => ({
        server_id: server.id,
        name: server.name,
        environment: server.environment,
        criticality: server.criticality,
        state: server.lifecycleState,
        connection_mode: server.connectionMode
      })),
      has_more: hasMore
    };
    if (hasMore) result.next_cursor = Buffer.from(String(offset + page.length)).toString("base64url");
    return result;
  }

  private getServer(input: JsonObject): JsonObject {
    const server = this.requireServer(asString(input.server_id));
    return {
      server_id: server.id,
      name: server.name,
      environment: server.environment,
      owner: server.owner,
      criticality: server.criticality,
      state: server.lifecycleState,
      connection_mode: server.connectionMode,
      labels: server.labels
    };
  }

  private listProfiles(input: JsonObject): JsonObject {
    const profiles = this.getAllProfiles()
      .filter((profile) => !input.connection_mode || profile.connectionMode === input.connection_mode)
      .filter((profile) => !input.environment || profile.environments.includes(input.environment as Environment))
      .map((profile) => ({
        access_profile_id: profile.id,
        name: profile.name,
        connection_mode: profile.connectionMode,
        max_ttl_seconds: profile.maxTtlSeconds
      }));
    return { profiles };
  }

  private addServer(input: JsonObject, context: RequestContext): JsonObject {
    return this.idempotent("secureit.servers.add", input, () => {
      const endpoint = input.management_endpoint as { address: string; port: number };
      assertSafeDemoEndpoint(endpoint.address, endpoint.port);
      const profile = this.requireProfile(asString(input.access_profile_id));
      if (profile.connectionMode !== input.connection_mode) {
        throw new DomainError("POLICY_DENIED", "El perfil no coincide con el modo de conexión");
      }
      if (!profile.environments.includes(input.environment as Environment)) {
        throw new DomainError("POLICY_DENIED", "El perfil no está autorizado en ese ambiente");
      }
      if (this.getAllServers().some((server) => server.name === input.name)) {
        throw new DomainError("CONFLICT", "Ya existe un servidor con ese nombre");
      }

      const id = randomUUID();
      const server: ServerRecord = {
        id,
        name: asString(input.name),
        environment: input.environment as ServerRecord["environment"],
        owner: asString(input.owner),
        criticality: input.criticality as ServerRecord["criticality"],
        lifecycleState: "pending",
        connectionMode: input.connection_mode as ServerRecord["connectionMode"],
        labels: (input.labels as Record<string, string> | undefined) ?? {},
        endpoint: structuredClone(endpoint),
        expectedHostIdentity: asString(input.expected_host_identity),
        accessProfileId: profile.id,
        bindingReady: false,
        identityReady: false
      };
      this.saveServer(server);
      void context;
      return {
        server_id: id,
        state: "pending",
        admin_action_required: true,
        next_step: "Un administrador debe aprobar el binding y verificar la identidad fuera de MCP."
      };
    });
  }

  private enrollmentStatus(input: JsonObject): JsonObject {
    const server = this.requireServer(asString(input.server_id));
    const ready = server.bindingReady && server.identityReady;
    return {
      server_id: server.id,
      state: server.lifecycleState,
      binding_ready: server.bindingReady,
      identity_ready: server.identityReady,
      admin_action_required: ready
        ? null
        : "Aprobar el binding y completar la verificación de identidad en la consola administrativa."
    };
  }

  private verifyServer(input: JsonObject, context: RequestContext): JsonObject {
    return this.idempotent("secureit.servers.verify", input, () => {
      const server = this.requireServer(asString(input.server_id));
      if (server.lifecycleState !== "pending") {
        throw new DomainError("INVALID_STATE", "Solo se verifican servidores pendientes");
      }
      if (!server.bindingReady || !server.identityReady) {
        throw new DomainError("POLICY_DENIED", "Falta completar el enrolamiento administrativo");
      }
      const job = this.createJob("completed", [server], true);
      void context;
      return { job_id: job.id, status: job.status, server_id: server.id };
    });
  }

  private listActions(input: JsonObject): JsonObject {
    return {
      actions: this.getAllActions()
        .filter((action) => !input.environment || action.environments.includes(input.environment as Environment))
        .map((action) => ({
          action_id: action.id,
          version: action.version,
          description: action.description,
          risk: action.risk,
          parameter_schema: action.parameterSchema
        }))
    };
  }

  private executeAction(input: JsonObject, context: RequestContext): JsonObject {
    return this.idempotent("secureit.ssh.execute_action", input, () => {
      const action = this.getActionByIdVersion(asString(input.action_id), Number(input.action_version));
      if (!action) throw new DomainError("NOT_FOUND", "La acción o versión no existe");
      try {
        validateJsonSchema(action.parameterSchema, input.parameters, action.id);
      } catch {
        throw new DomainError("INVALID_ARGUMENT", "Los parámetros no cumplen el esquema de la acción");
      }
      const servers = this.resolveManagedServers(asStringArray(input.server_ids));
      if (servers.length > action.maxTargets) {
        throw new DomainError("POLICY_DENIED", "La solicitud excede el máximo de objetivos de la acción");
      }
      if (servers.some((server) => !action.environments.includes(server.environment))) {
        throw new DomainError("POLICY_DENIED", "La acción no está autorizada en el ambiente solicitado");
      }

      const manifest = {
        action: { id: action.id, version: action.version },
        parameters: input.parameters,
        target_ids: servers.map((server) => server.id).sort(),
        requester: context.subject
      };
      const requiresApproval = servers.some((server) => server.environment === "staging" || server.environment === "prod");
      const job = this.createJob(requiresApproval ? "awaiting_approval" : "completed", servers, !requiresApproval);
      const response: JsonObject = {
        job_id: job.id,
        status: job.status,
        risk: action.risk,
        manifest_hash: sha256(manifest),
        target_count: servers.length
      };
      if (requiresApproval) response.approval_request_id = randomUUID();
      return response;
    });
  }

  private executeCommand(input: JsonObject, context: RequestContext): JsonObject {
    return this.idempotent("secureit.ssh.execute_command", input, () => {
      const servers = this.resolveManagedServers(asStringArray(input.server_ids));
      const scriptDigest = sha256(asString(input.script));
      const manifestHash = sha256({
        interpreter: input.interpreter,
        script_digest: scriptDigest,
        timeout_seconds: input.timeout_seconds,
        target_ids: servers.map((server) => server.id).sort(),
        requester: context.subject
      });
      const job = this.createJob("awaiting_approval", servers, false);
      return {
        job_id: job.id,
        status: job.status,
        risk: "high",
        script_digest: scriptDigest,
        manifest_hash: manifestHash,
        target_count: servers.length,
        approval_request_id: randomUUID()
      };
    });
  }

  private getJob(input: JsonObject): JsonObject {
    const job = this.getJobById(asString(input.job_id));
    if (!job) throw new DomainError("NOT_FOUND", "El trabajo no existe");
    const includeOutput = input.include_output === true;
    return {
      job_id: job.id,
      status: job.status,
      created_at: job.createdAt,
      expires_at: job.expiresAt,
      results: job.results.map((result) => ({
        server_id: result.serverId,
        server_alias: result.serverAlias,
        status: result.status,
        exit_code: result.exitCode,
        stdout_excerpt: includeOutput ? result.stdoutExcerpt : null,
        stderr_excerpt: includeOutput ? result.stderrExcerpt : null,
        truncated: result.truncated,
        secret_detected: result.secretDetected
      }))
    };
  }

  private cancelJob(input: JsonObject, context: RequestContext): JsonObject {
    return this.idempotent("secureit.jobs.cancel", input, () => {
      const job = this.getJobById(asString(input.job_id));
      if (!job) throw new DomainError("NOT_FOUND", "El trabajo no existe");
      const cancellable = ["awaiting_approval", "queued", "running"].includes(job.status);
      if (cancellable) {
        job.status = "cancelled";
        this.saveJob(job);
      }
      void context;
      return { job_id: job.id, status: job.status, cancellation_requested: cancellable };
    });
  }

  private rotateCredential(input: JsonObject, context: RequestContext): JsonObject {
    return this.idempotent("secureit.credentials.rotate", input, () => {
      const servers = this.resolveManagedServers(asStringArray(input.server_ids));
      const profile = this.requireProfile(asString(input.access_profile_id));
      if (servers.some((server) => server.accessProfileId !== profile.id)) {
        throw new DomainError("POLICY_DENIED", "El perfil no está asociado a todos los objetivos");
      }
      void context;
      return {
        rotation_job_id: randomUUID(),
        status: "awaiting_approval",
        target_count: servers.length,
        admin_action_required: true
      };
    });
  }

  private createJob(status: JobRecord["status"], servers: ServerRecord[], withOutput: boolean): JobRecord {
    const now = new Date();
    const expires = new Date(now.getTime() + 15 * 60 * 1000);
    const job: JobRecord = {
      id: randomUUID(),
      status,
      createdAt: now.toISOString(),
      expiresAt: expires.toISOString(),
      results: servers.map((server) => {
        const output = withOutput
          ? sanitizeOutput("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/demo 100 42 58 42% /", 65_536)
          : null;
        return {
          serverId: server.id,
          serverAlias: server.name,
          status: status === "completed" ? "completed" : status,
          exitCode: status === "completed" ? 0 : null,
          stdoutExcerpt: output?.excerpt ?? null,
          stderrExcerpt: null,
          truncated: output?.truncated ?? false,
          secretDetected: output?.secretDetected ?? false
        };
      })
    };
    this.saveJob(job);
    return job;
  }

  private idempotent(toolName: string, input: JsonObject, create: () => JsonObject): JsonObject {
    const key = asString(input.idempotency_key);
    const compoundKey = `${toolName}:${key}`;
    const fingerprint = sha256(input);

    const existing = this.db
      .prepare("SELECT fingerprint, response FROM idempotency WHERE compound_key = ?")
      .get(compoundKey) as { fingerprint: string; response: string } | undefined;

    if (existing) {
      if (existing.fingerprint !== fingerprint) {
        throw new DomainError("CONFLICT", "La clave de idempotencia ya se usó con otra solicitud");
      }
      return JSON.parse(existing.response) as JsonObject;
    }

    const response = create();
    this.db
      .prepare("INSERT INTO idempotency (compound_key, fingerprint, response) VALUES (?, ?, ?)")
      .run(compoundKey, fingerprint, JSON.stringify(response));
    return response;
  }

  private resolveManagedServers(ids: string[]): ServerRecord[] {
    return ids.map((id) => {
      const server = this.requireServer(id);
      if (server.lifecycleState !== "managed") {
        throw new DomainError("POLICY_DENIED", "Un objetivo no está administrado o está bloqueado");
      }
      return server;
    });
  }

  private decodeCursor(cursor: string | undefined): number {
    if (!cursor) return 0;
    const decoded = Buffer.from(cursor, "base64url").toString("utf8");
    if (!/^\d+$/.test(decoded)) throw new DomainError("INVALID_ARGUMENT", "Cursor no válido");
    const offset = Number(decoded);
    if (!Number.isSafeInteger(offset) || offset < 0) throw new DomainError("INVALID_ARGUMENT", "Cursor no válido");
    return offset;
  }

  private hasLabel(labels: Record<string, string>, filter: string): boolean {
    const separator = filter.indexOf("=");
    if (separator < 0) return Object.hasOwn(labels, filter);
    return labels[filter.slice(0, separator)] === filter.slice(separator + 1);
  }

  private objectIds(input: unknown): string[] {
    if (input === null || typeof input !== "object") return [];
    const value = input as Record<string, unknown>;
    const ids = [value.server_id, value.job_id, ...(Array.isArray(value.server_ids) ? value.server_ids : [])];
    return ids.filter((candidate): candidate is string => typeof candidate === "string").slice(0, 100);
  }

  private audit(
    context: RequestContext,
    operation: string,
    outcome: AuditEvent["outcome"],
    objectIds: string[],
    reasonCode: string
  ): void {
    const event: AuditEvent = {
      id: randomUUID(),
      occurredAt: new Date().toISOString(),
      subject: context.subject || "anonymous",
      operation,
      outcome,
      objectIds,
      reasonCode
    };
    this.db
      .prepare("INSERT INTO audit_events (id, occurred_at, data) VALUES (?, ?, ?)")
      .run(event.id, event.occurredAt, JSON.stringify(event));
  }
}
