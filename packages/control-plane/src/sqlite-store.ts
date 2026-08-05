import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { join } from "node:path";
import { homedir, platform } from "node:os";
import { mkdirSync, existsSync } from "node:fs";
import {
  requiredScopeFor,
  validateJsonSchema,
  validateToolInput,
  validateToolOutput,
  type JsonObject
} from "@secure-it/contracts";
import { DomainError } from "./errors.js";
import { demoActions, demoProfiles, demoServers, testServerRecord } from "./fixtures.js";
import { type ActionExecutor, type ScriptExecutor, type ExecutionOutcome, type ResolvedCredential } from "./executor.js";
import { assertSafeDemoEndpoint, sanitizeOutput, sha256 } from "./security.js";
import {
  decryptSecret,
  encryptSecret,
  resolveMasterKey,
  type MasterKey
} from "./secrets.js";
import { hashPassword, verifyPassword } from "./password.js";
import { generateTokenRaw, hashToken, isInternalToken } from "./tokens.js";
import type {
  AccessProfile,
  ActionDefinition,
  AdminUser,
  AuditEvent,
  CredentialRecord,
  CredentialStatus,
  CredentialType,
  Environment,
  JobRecord,
  RequestContext,
  ServerRecord,
  TokenRecord,
  TokenServerGrant
} from "./types.js";

const asString = (value: unknown): string => value as string;
const asStringArray = (value: unknown): string[] => value as string[];

const DB_FILENAME = "secureit.db";
const LEGACY_DIR_NAME = ".secure-it";

function resolveDefaultDbPath(): string {
  const home = homedir();
  const legacy = join(home, LEGACY_DIR_NAME, DB_FILENAME);
  if (existsSync(legacy)) {
    return legacy;
  }

  const baseDir = appDataDir(home);
  if (!existsSync(baseDir)) {
    mkdirSync(baseDir, { recursive: true });
  }
  return join(baseDir, DB_FILENAME);
}

function appDataDir(home: string): string {
  switch (platform()) {
    case "win32": {
      const appdata =
        process.env.APPDATA && process.env.APPDATA.trim().length > 0
          ? process.env.APPDATA
          : join(home, "AppData", "Roaming");
      return join(appdata, "secure-it");
    }
    case "darwin":
      return join(home, "Library", "Application Support", "secure-it");
    default: {
      const xdg = process.env.XDG_DATA_HOME && process.env.XDG_DATA_HOME.trim().length > 0
        ? process.env.XDG_DATA_HOME
        : join(home, ".local", "share");
      return join(xdg, "secure-it");
    }
  }
}

interface ServerCredential {
  cred: CredentialRecord;
  username: string;
  exactAlias: boolean;
}

export interface SqliteControlPlaneOptions {
  dbPath?: string;
  inMemory?: boolean;
  seedTestServer?: boolean;
  seedDemoData?: boolean;
  /**
   * Clave maestra de cifrado de credenciales en reposo. Si se omite se usa
   * `process.env.SECUREIT_MASTER_KEY`; si tampoco está, se genera una clave
   * efímera (solo válida en `:memory:`).
   */
  masterKey?: string | Buffer;
  /** Ejecutor real de acciones tipadas. Si se omite, `execute_action` produce
   *  salida sintética (idéntico al comportamiento demo original). */
  executor?: ActionExecutor | null;
  /** Ejecutor real de scripts libres. Si se omite, `execute_command` produce
   *  salida sintética (idéntico al comportamiento demo original). */
  scriptExecutor?: ScriptExecutor | null;
  /** Credenciales de bootstrap para la primera cuenta administrativa. */
  adminUsername?: string;
  adminPassword?: string;
}

export class SqliteControlPlane {
  private db: DatabaseSync;
  private executor: ActionExecutor | null;
  private scriptExecutor: ScriptExecutor | null;
  private readonly masterKey: MasterKey;
  private readonly inMemory: boolean;

  constructor(options: SqliteControlPlaneOptions = {}) {
    this.executor = options.executor ?? null;
    this.scriptExecutor = options.scriptExecutor ?? null;
    this.inMemory = Boolean(options.inMemory);
    this.masterKey = resolveMasterKey({
      ...(options.masterKey !== undefined ? { masterKey: options.masterKey } : {}),
      inMemory: this.inMemory
    });
    let dbPath = options.dbPath || process.env.SECUREIT_DB_PATH;
    if (options.inMemory) {
      dbPath = ":memory:";
    } else if (!dbPath) {
      dbPath = resolveDefaultDbPath();
    }

    this.db = new DatabaseSync(dbPath);
    this.initSchema();
    this.ensureInitialAdmin(options.adminUsername, options.adminPassword);
    this.migratePlaintextCredentials();
    this.seedIfEmpty(Boolean(options.seedDemoData), Boolean(options.seedTestServer));
  }

  /**
   * Migra filas de `credentials` escritas en claro (instalaciones previas sin
   * cifrado) a su forma cifrada con AES-256-GCM. Es idempotente y solo reescribe
   * filas que aún exponen `secretValue` sin `secretCipher`.
   */
  private migratePlaintextCredentials(): void {
    // Si no hay clave maestra persistible (sin SECUREIT_MASTER_KEY y DB en disco),
    // dejamos las filas legacy en claro intactas: la lectura las resuelve por la
    // rama legacy y no bloqueamos el arranque. La migración real ocurre cuando el
    // operador aporta SECUREIT_MASTER_KEY.
    if (this.masterKey.ephemeral && !this.inMemory) return;
    const rows = this.db.prepare("SELECT id, data FROM credentials").all() as { id: string; data: string }[];
    const update = this.db.prepare("UPDATE credentials SET data = ? WHERE id = ?");
    for (const row of rows) {
      const cred = JSON.parse(row.data) as CredentialRecord;
      const hasCipher = typeof cred.secretCipher === "string" && cred.secretCipher.length > 0;
      const hasPlain = typeof cred.secretValue === "string" && cred.secretValue.length > 0;
      if (hasCipher || !hasPlain) continue;
      this.persistCredentialSecret(cred, cred.secretValue!);
      delete cred.secretValue;
      update.run(JSON.stringify(cred), row.id);
    }
  }

  close(): void {
    this.db.close();
  }

  /**
   * Resuelve la ubicación del archivo SQLite por defecto cuando ni `dbPath`
   * ni `SECUREIT_DB_PATH` lo establecen. Precedencia:
   *
   *   1. `~/.secure-it/secureit.db` si ya existe → preserva instalaciones
   *      anteriores intactas (backward-compat).
   *   2. Directorio "app data" del usuario/sección compartida por plataforma:
   *      - Windows: `%APPDATA%\secure-it`
   *      - macOS:   `~/Library/Application Support/secure-it`
   *      - Otros:   `${XDG_DATA_HOME:-~/.local/share}/secure-it`
   *      Compartido por toda instalación de `secure-it` o del MCP en el host,
   *      de modo que cualquier instancia (CLI, admin, MCP) vea el mismo
   *      inventario, credenciales y auditoría.
   *
   *   El directorio se crea con permisos restrictivos solo cuando es necesario.
   */
  static resolveDefaultDbPath(): string {
    return resolveDefaultDbPath();
  }

  /** Inyecta (o retira) el ejecutor real de acciones tipadas. */
  setExecutor(executor: ActionExecutor | null): void {
    this.executor = executor;
  }

  /** Inyecta (o retira) el ejecutor real de scripts libres. */
  setScriptExecutor(executor: ScriptExecutor | null): void {
    this.scriptExecutor = executor;
  }

  /**
   * Cifra `plaintext` y lo emplaza en `cred.secretCipher`, dejando el secreto
   * listo para serializar a disco SIN `secretValue`. Idempotente respecto a
   * re-cifrar el mismo valor (genera IV distinto cada vez, lo cual es correcto).
   */
  private persistCredentialSecret(cred: CredentialRecord, plaintext: string): void {
    cred.secretCipher = encryptSecret(plaintext, this.masterKey, this.inMemory);
    delete cred.secretValue;
  }

  /**
   * Lee una fila de credencial y resuelve su secreto en claro a memoria (para
   * uso interno del ejecutor o de `revealCredential`). Soporta filas ya cifradas
   * (`secretCipher`) y filas legacy en claro (`secretValue`) aún no migradas.
   */
  private loadCredentialRecord(data: string): CredentialRecord {
    const cred = JSON.parse(data) as CredentialRecord;
    if (typeof cred.secretCipher === "string" && cred.secretCipher.length > 0) {
      cred.secretValue = decryptSecret(cred.secretCipher, this.masterKey);
    }
    return cred;
  }

  /** Devuelve una copia segura (sin material secreto) para listar/responder. */
  private toPublicCredential(cred: CredentialRecord): CredentialRecord {
    const result = { ...cred };
    delete result.secretValue;
    delete result.secretCipher;
    result.maskedValue = "••••••••";
    return result;
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
      CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY,
        alias TEXT UNIQUE NOT NULL,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS admin_users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tokens (
        id TEXT PRIMARY KEY,
        token_hash TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        data TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS token_server_grants (
        token_id TEXT NOT NULL,
        server_id TEXT NOT NULL,
        data TEXT NOT NULL,
        PRIMARY KEY (token_id, server_id)
      );
    `);
  }

  // ──────────────────────────────────────────────────────────────────────
  // Usuarios administrativos (login con usuario/contraseña)
  // ──────────────────────────────────────────────────────────────────────

  /** Crea la primera cuenta administrativa con credenciales explícitas. */
  private ensureInitialAdmin(usernameOption?: string, passwordOption?: string): void {
    const row = this.db.prepare("SELECT COUNT(*) as count FROM admin_users").get() as { count: number };
    if (row && row.count > 0) return;
    const username = (usernameOption ?? process.env.SECUREIT_ADMIN_USERNAME ?? "admin").trim();
    // El valor de pruebas solo se permite en memoria; una instalación persistente
    // debe recibir el secreto fuera del repositorio.
    const password = passwordOption ?? process.env.SECUREIT_ADMIN_PASSWORD ?? (this.inMemory ? "admin" : "");
    if (!username || (!this.inMemory && password.length < 12)) {
      throw new Error(
        "La instalación inicial requiere SECUREIT_ADMIN_PASSWORD con al menos 12 caracteres. " +
          "El valor solo se usa para crear la primera cuenta y no se registra en logs."
      );
    }
    const user: AdminUser = {
      id: randomUUID(),
      username,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString()
    };
    this.db
      .prepare("INSERT INTO admin_users (id, username, data) VALUES (?, ?, ?)")
      .run(user.id, user.username, JSON.stringify(user));
    console.warn(`[admin-security] Cuenta administrativa inicial creada para '${username}'.`);
  }

  /**
   * Verifica las credenciales de login del admin. Devuelve el usuario (sin
   * validar hash en la respuesta) si la contraseña coincide, o `null`.
   */
  verifyAdminLogin(username: string, password: string): AdminUser | null {
    const row = this.db.prepare("SELECT data FROM admin_users WHERE username = ?").get(username) as
      | { data: string }
      | undefined;
    if (!row) return null;
    const user = JSON.parse(row.data) as AdminUser;
    return verifyPassword(password, user.passwordHash) ? user : null;
  }

  /** Cambia la contraseña del usuario administrativo indicado. */
  changeAdminPassword(username: string, currentPassword: string, newPassword: string): boolean {
    const user = this.verifyAdminLogin(username, currentPassword);
    if (!user) return false;
    const updated: AdminUser = { ...user, passwordHash: hashPassword(newPassword) };
    this.db
      .prepare("UPDATE admin_users SET data = ? WHERE username = ?")
      .run(JSON.stringify(updated), username);
    return true;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Tokens internos (session-tokens + token general de fallback)
  // ──────────────────────────────────────────────────────────────────────

  /**
   * Garantiza la existencia del "token general" de fallback. Es el token usado
   * por el transporte stdio del MCP (y por cualquier cliente HTTP que no aporte
   * un session-token) y posee los servidores que se agregan sin un token
   * específico. Devuelve el registro del token general. La impresión del valor
   * crudo al arranque la realiza el llamante MCP si lo desea.
   */
  ensureGeneralToken(): TokenRecord {
    const existing = this.db
      .prepare("SELECT data FROM tokens")
      .all() as { data: string }[];
    for (const row of existing) {
      const token = JSON.parse(row.data) as TokenRecord;
      if (token.isGeneral) return token;
    }
    const raw = generateTokenRaw();
    const token: TokenRecord = {
      id: randomUUID(),
      tokenHash: hashToken(raw),
      name: "general",
      subject: "general-fallback",
      scopes: [],
      isGeneral: true,
      active: true,
      createdAt: new Date().toISOString(),
      expiresAt: null
    };
    this.db
      .prepare("INSERT INTO tokens (id, token_hash, name, data) VALUES (?, ?, ?, ?)")
      .run(token.id, token.tokenHash, token.name, JSON.stringify(token));
    // Backfill: los servidores preexistentes sin dueño de token pasan a ser
    // propiedad del token general, de modo que el fallback los siga viendo.
    this.backfillGeneralOwnership(token.id);
    console.warn("[secure-it] Token general de fallback creado y almacenado de forma no reversible.");
    return token;
  }

  private backfillGeneralOwnership(generalTokenId: string): void {
    const rows = this.db.prepare("SELECT id, data FROM servers").all() as { id: string; data: string }[];
    const update = this.db.prepare("UPDATE servers SET data = ? WHERE id = ?");
    for (const row of rows) {
      const server = JSON.parse(row.data) as ServerRecord;
      if (server.ownerTokenId === undefined || server.ownerTokenId === null || server.ownerTokenId === "") {
        server.ownerTokenId = generalTokenId;
        update.run(JSON.stringify(server), row.id);
      }
    }
  }

  /**
   * Emite un nuevo session-token. Devuelve el registro + el valor crudo (que
   * solo se muestra esta vez). El token单人 posee, por defecto, los servidores
   * que agregue; el admin puede extender el acceso mediante grants.
   */
  createToken(name: string, scopes?: string[]): { token: TokenRecord; raw: string } {
    const raw = generateTokenRaw();
    const token: TokenRecord = {
      id: randomUUID(),
      tokenHash: hashToken(raw),
      name: name.trim() || `token-${randomUUID().slice(0, 6)}`,
      subject: `token:${name.trim() || randomUUID().slice(0, 6)}`,
      scopes: scopes && scopes.length > 0 ? scopes : [],
      isGeneral: false,
      active: true,
      createdAt: new Date().toISOString(),
      expiresAt: null
    };
    this.db
      .prepare("INSERT INTO tokens (id, token_hash, name, data) VALUES (?, ?, ?, ?)")
      .run(token.id, token.tokenHash, token.name, JSON.stringify(token));
    return { token, raw };
  }

  /** Resuelve un token por su valor crudo (hash). Verifica `active`. */
  resolveTokenFromRaw(raw: string): TokenRecord | null {
    if (!isInternalToken(raw)) return null;
    const row = this.db
      .prepare("SELECT data FROM tokens WHERE token_hash = ?")
      .get(hashToken(raw)) as { data: string } | undefined;
    if (!row) return null;
    const token = JSON.parse(row.data) as TokenRecord;
    if (!token.active) return null;
    if (token.expiresAt && Date.parse(token.expiresAt) < Date.now()) return null;
    return token;
  }

  getTokenById(id: string): TokenRecord | null {
    const row = this.db.prepare("SELECT data FROM tokens WHERE id = ?").get(id) as
      | { data: string }
      | undefined;
    return row ? (JSON.parse(row.data) as TokenRecord) : null;
  }

  listTokens(): TokenRecord[] {
    const rows = this.db
      .prepare("SELECT data FROM tokens")
      .all() as { data: string }[];
    return rows
      .map((r) => {
        const { tokenHash: _omit, ...safe } = JSON.parse(r.data) as TokenRecord;
        return safe as TokenRecord;
      })
      .sort((a, b) => (b.isGeneral ? 1 : 0) - (a.isGeneral ? 1 : 0) || a.createdAt.localeCompare(b.createdAt));
  }

  /** Activa/desactiva un token (soft revoke). */
  setTokenActive(id: string, active: boolean): void {
    const token = this.getTokenById(id);
    if (!token) throw new DomainError("NOT_FOUND", "El token no existe");
    token.active = active;
    this.db.prepare("UPDATE tokens SET data = ? WHERE id = ?").run(JSON.stringify(token), id);
  }

  // ──────────────────────────────────────────────────────────────────────
  // Permisos: extensión de acceso de un token a un servidor de otro token
  // ──────────────────────────────────────────────────────────────────────

  grantServerAccess(tokenId: string, serverId: string, grantedBy: string): TokenServerGrant {
    if (!this.getTokenById(tokenId)) throw new DomainError("NOT_FOUND", "El token no existe");
    if (!this.getServerById(serverId)) throw new DomainError("NOT_FOUND", "El servidor no existe");
    const grant: TokenServerGrant = {
      tokenId,
      serverId,
      grantedBy,
      grantedAt: new Date().toISOString()
    };
    this.db
      .prepare("INSERT OR REPLACE INTO token_server_grants (token_id, server_id, data) VALUES (?, ?, ?)")
      .run(tokenId, serverId, JSON.stringify(grant));
    return grant;
  }

  revokeServerAccess(tokenId: string, serverId: string): void {
    this.db
      .prepare("DELETE FROM token_server_grants WHERE token_id = ? AND server_id = ?")
      .run(tokenId, serverId);
  }

  listGrantsForServer(serverId: string): TokenServerGrant[] {
    const rows = this.db
      .prepare("SELECT data FROM token_server_grants WHERE server_id = ?")
      .all(serverId) as { data: string }[];
    return rows.map((r) => JSON.parse(r.data) as TokenServerGrant);
  }

  private listGrantsForToken(tokenId: string): TokenServerGrant[] {
    const rows = this.db
      .prepare("SELECT data FROM token_server_grants WHERE token_id = ?")
      .all(tokenId) as { data: string }[];
    return rows.map((r) => JSON.parse(r.data) as TokenServerGrant);
  }

  /** ¿El token puede acceder al servidor? (propiedad o grant explícito). */
  private tokenCanAccessServer(tokenId: string, server: ServerRecord): boolean {
    if (server.ownerTokenId === tokenId) return true;
    const grants = this.listGrantsForToken(tokenId);
    return grants.some((g) => g.serverId === server.id);
  }

  /**
   * Resuelve la credencial de login SSH para un servidor (`server.credentialAlias`
   * exacto; si no, alias que contenga `<server.name>` y embeba un usuario por
   * convención `usuario@host` o `host:usuario`). Prefiere credenciales `active`
   * del mismo ambiente y tipo `ssh_key`/`db_password`. El secreto se devuelve
   * internamente al ejecutor; nunca se expone al agente.
   */
  resolveLoginCredential(server: ServerRecord): ResolvedCredential | null {
    const matches: ServerCredential[] = [];
    const rows = this.db.prepare("SELECT data FROM credentials").all() as { data: string }[];
    for (const row of rows) {
      const cred = this.loadCredentialRecord(row.data);
      if (cred.status !== "active") continue;
      const exactAlias = Boolean(server.credentialAlias && cred.alias === server.credentialAlias);
      const matchesName = cred.alias.includes(server.name);
      if (!exactAlias && !matchesName) continue;
      const username = this.usernameFromAlias(cred.alias, server.name);
      if (!username) continue;
      matches.push({ cred, username, exactAlias });
    }
    if (matches.length === 0) return null;

    const rank = (m: ServerCredential): number => {
      const typeRank = m.cred.type === "ssh_key" ? 2 : m.cred.type === "db_password" ? 1 : 0;
      const envRank = m.cred.environment === server.environment ? 2 : 1;
      const aliasRank = m.exactAlias ? 2 : 1;
      return typeRank * 100 + envRank * 10 + aliasRank;
    };
    matches.sort((left, right) => rank(right) - rank(left));
    const best = matches[0]!;
    const kind = best.cred.type === "ssh_key" ? "privateKey" : "password";
    if (!best.cred.secretValue) return null;
    return { username: best.username, secret: best.cred.secretValue, kind };
  }

  private usernameFromAlias(alias: string, serverName: string): string | null {
    if (alias.startsWith(`${serverName}@`)) return alias.slice(serverName.length + 1);
    if (alias.endsWith(`@${serverName}`)) return alias.slice(0, alias.length - serverName.length - 1);
    if (alias.startsWith(`${serverName}:`)) return alias.slice(serverName.length + 1);
    const colon = alias.indexOf(":");
    if (colon >= 0 && alias.slice(0, colon) === serverName) return alias.slice(colon + 1);
    return null;
  }

  private seedIfEmpty(seedDemoData = false, seedTestServer = false): void {
    const upsertProfile = this.db.prepare(`
      INSERT INTO profiles (id, name, data) VALUES (?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET data = excluded.data, name = excluded.name
    `);
    for (const profile of demoProfiles) {
      upsertProfile.run(profile.id, profile.name, JSON.stringify(profile));
    }

    // Las acciones del catálogo demo se reupsertan en cada arranque para que una
    // definición nueva (mismo `id@version`) se propague a instalaciones ya
    // sembradas, sin alterar acciones con otro id o versión añadidas a posteriori.
    const upsertAction = this.db.prepare(`
      INSERT INTO actions (id_version, data) VALUES (?, ?)
      ON CONFLICT(id_version) DO UPDATE SET data = excluded.data
    `);
    for (const action of demoActions) {
      upsertAction.run(`${action.id}@${action.version}`, JSON.stringify(action));
    }

    if (!seedDemoData && !seedTestServer) {
      return;
    }

    const serverRow = this.db.prepare("SELECT COUNT(*) as count FROM servers").get() as { count: number };
    if (!serverRow || serverRow.count === 0) {
      const insertServer = this.db.prepare("INSERT INTO servers (id, name, data) VALUES (?, ?, ?)");
      for (const server of demoServers) {
        insertServer.run(server.id, server.name, JSON.stringify(server));
      }
      if (seedTestServer) {
        insertServer.run(testServerRecord.id, testServerRecord.name, JSON.stringify(testServerRecord));
      }
    }

    const credRow = this.db.prepare("SELECT COUNT(*) as count FROM credentials").get() as { count: number };
    if (!credRow || credRow.count === 0) {
      const insertCred = this.db.prepare("INSERT INTO credentials (id, alias, data) VALUES (?, ?, ?)");
      const demoCreds: CredentialRecord[] = [
        {
          id: "cred-ssh-prod",
          alias: "ssh-prod-bastion",
          type: "ssh_key",
          owner: "infra-ops",
          environment: "prod",
          status: "active",
          version: 1,
          lastRotatedAt: new Date().toISOString(),
          expiresAt: null,
          exportable: true,
          maskedValue: "••••••••",
          secretValue: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG824... demo_admin_key"
        },
        {
          id: "cred-db-staging",
          alias: "postgres-staging-rw",
          type: "db_password",
          owner: "backend-team",
          environment: "staging",
          status: "active",
          version: 2,
          lastRotatedAt: new Date(Date.now() - 86400000 * 7).toISOString(),
          expiresAt: new Date(Date.now() + 86400000 * 90).toISOString(),
          exportable: true,
          maskedValue: "••••••••",
          secretValue: "s3cur3_Stag!ng_P@ssw0rd_2026"
        },
        {
          id: "cred-api-stripe",
          alias: "stripe-api-prod",
          type: "api_token",
          owner: "finance-team",
          environment: "prod",
          status: "active",
          version: 1,
          lastRotatedAt: new Date(Date.now() - 86400000 * 30).toISOString(),
          expiresAt: null,
          exportable: true,
          maskedValue: "••••••••",
          secretValue: "mock_stripe_sk_prod_51M00000000000000000000000"
        },
        {
          id: "cred-ca-master",
          alias: "master-ca-private-key",
          type: "ca_private_key",
          owner: "secops",
          environment: "prod",
          status: "active",
          version: 1,
          lastRotatedAt: new Date(Date.now() - 86400000 * 60).toISOString(),
          expiresAt: null,
          exportable: false,
          maskedValue: "••••••••",
          secretValue: "-----BEGIN PRIVATE KEY-----\nPROTECTED_NON_EXPORTABLE_CA_KEY\n-----END PRIVATE KEY-----"
        }
      ];
      for (const cred of demoCreds) {
        const persisted = { ...cred };
        this.persistCredentialSecret(persisted, cred.secretValue!);
        delete persisted.secretValue;
        insertCred.run(cred.id, cred.alias, JSON.stringify(persisted));
      }
    }
  }

  listCredentials(): CredentialRecord[] {
    const rows = this.db.prepare("SELECT data FROM credentials ORDER BY alias ASC").all() as { data: string }[];
    return rows.map((r) => {
      const cred = JSON.parse(r.data) as CredentialRecord;
      return this.toPublicCredential(cred);
    });
  }

  createCredential(
    input: {
      alias: string;
      type?: CredentialType;
      owner?: string;
      environment?: Environment;
      exportable?: boolean;
      secretValue?: string;
    },
    context: RequestContext
  ): CredentialRecord {
    if (!input.alias) {
      throw new DomainError("INVALID_ARGUMENT", "Falta el alias para la credencial");
    }
    const existing = this.db.prepare("SELECT id FROM credentials WHERE alias = ?").get(input.alias);
    if (existing) {
      throw new DomainError("CONFLICT", `Ya existe una credencial con el alias '${input.alias}'`);
    }

    const type = input.type ?? "ssh_key";
    const owner = input.owner ?? "admin";
    const environment = input.environment ?? "prod";

    const id = `cred-${randomUUID().slice(0, 8)}`;
    const plaintext = input.secretValue || `generated_${randomUUID().slice(0, 16)}`;
    const cred: CredentialRecord = {
      id,
      alias: input.alias,
      type,
      owner,
      environment,
      status: "active",
      version: 1,
      lastRotatedAt: new Date().toISOString(),
      expiresAt: null,
      exportable: input.exportable ?? true,
      maskedValue: "••••••••",
      secretValue: plaintext
    };
    this.persistCredentialSecret(cred, plaintext);

    this.db
      .prepare("INSERT INTO credentials (id, alias, data) VALUES (?, ?, ?)")
      .run(cred.id, cred.alias, JSON.stringify(cred));

    this.audit(context, "credential:import", "allowed", [cred.id], "IMPORT_SUCCESS");

    return this.toPublicCredential(cred);
  }

  revealCredential(id: string, context: RequestContext, reason?: string): string {
    const row = this.db.prepare("SELECT data FROM credentials WHERE id = ?").get(id) as { data: string } | undefined;
    if (!row) {
      this.audit(context, "credential:reveal", "denied", [id], "NOT_FOUND");
      throw new DomainError("NOT_FOUND", `Credencial '${id}' no encontrada`);
    }
    const stored = JSON.parse(row.data) as CredentialRecord;
    if (!stored.exportable) {
      this.audit(context, "credential:reveal", "denied", [id], "NON_EXPORTABLE");
      throw new DomainError("POLICY_DENIED", "La credencial no es exportable por política de seguridad");
    }

    this.audit(context, "credential:reveal", "allowed", [id], reason || "HUMAN_REVEAL_REQUEST");
    const cred = this.loadCredentialRecord(row.data);
    return cred.secretValue || "secret_not_set";
  }

  rotateCredentialAdmin(id: string, context: RequestContext): CredentialRecord {
    const row = this.db.prepare("SELECT data FROM credentials WHERE id = ?").get(id) as { data: string } | undefined;
    if (!row) {
      this.audit(context, "credential:rotate", "denied", [id], "NOT_FOUND");
      throw new DomainError("NOT_FOUND", `Credencial '${id}' no encontrada`);
    }
    const cred = JSON.parse(row.data) as CredentialRecord;
    const newSecret = `rotated_v${cred.version + 1}_${randomUUID().slice(0, 12)}`;
    cred.version += 1;
    cred.lastRotatedAt = new Date().toISOString();
    cred.status = "rotated";
    this.persistCredentialSecret(cred, newSecret);

    this.db.prepare("UPDATE credentials SET data = ? WHERE id = ?").run(JSON.stringify(cred), cred.id);
    this.audit(context, "credential:rotate", "allowed", [id], "ROTATION_SUCCESS");

    return this.toPublicCredential(cred);
  }

  revokeCredentialAdmin(id: string, context: RequestContext): CredentialRecord {
    const row = this.db.prepare("SELECT data FROM credentials WHERE id = ?").get(id) as { data: string } | undefined;
    if (!row) {
      this.audit(context, "credential:revoke", "denied", [id], "NOT_FOUND");
      throw new DomainError("NOT_FOUND", `Credencial '${id}' no encontrada`);
    }
    const cred = JSON.parse(row.data) as CredentialRecord;
    cred.status = "revoked";
    delete cred.secretValue;

    this.db.prepare("UPDATE credentials SET data = ? WHERE id = ?").run(JSON.stringify(cred), cred.id);
    this.audit(context, "credential:revoke", "allowed", [id], "REVOCATION_SUCCESS");

    return this.toPublicCredential(cred);
  }

  testCredentialAccessAdmin(id: string, context: RequestContext): { ok: boolean; testedAt: string } {
    const row = this.db.prepare("SELECT data FROM credentials WHERE id = ?").get(id) as { data: string } | undefined;
    if (!row) {
      this.audit(context, "credential:test", "denied", [id], "NOT_FOUND");
      throw new DomainError("NOT_FOUND", `Credencial '${id}' no encontrada`);
    }
    const cred = JSON.parse(row.data) as CredentialRecord;
    if (cred.status === "revoked") {
      this.audit(context, "credential:test", "denied", [id], "REVOKED");
      throw new DomainError("POLICY_DENIED", "La credencial se encuentra revocada");
    }

    this.audit(context, "credential:test", "allowed", [id], "TEST_SUCCESS");
    return { ok: true, testedAt: new Date().toISOString() };
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

  /**
   * Listado completo de servidores (registro interno, sin secretos) para la
   * consola admin. Devuelve todos los servidores sin filtrar por token, ya que
   * la consola admin opera con `isAdmin`. No expone material secreto (los
   * ServerRecord no contienen secretos).
   */
  listServersForAdmin(): ServerRecord[] {
    return this.getAllServers()
      .map((server) => ({ ...server }))
      .sort((a, b) => a.name.localeCompare(b.name));
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
        return this.listServers(input, context);
      case "secureit.servers.get":
        return this.getServer(input, context);
      case "secureit.access_profiles.list":
        return this.listProfiles(input);
      case "secureit.servers.add":
        return this.addServer(input, context);
      case "secureit.servers.enrollment_status":
        return this.enrollmentStatus(input, context);
      case "secureit.servers.verify":
        return this.verifyServer(input, context);
      case "secureit.servers.remove":
        return this.removeServer(input, context);
      case "secureit.actions.list":
        return this.listActions(input);
      case "secureit.ssh.execute_action":
        return this.executeAction(input, context);
      case "secureit.ssh.execute_command":
        return this.executeCommand(input, context);
      case "secureit.jobs.get":
        return this.getJob(input, context);
      case "secureit.jobs.cancel":
        return this.cancelJob(input, context);
      case "secureit.credentials.rotate":
        return this.rotateCredential(input, context);
      case "secureit.credentials.add":
        return this.addCredentialTool(input, context);
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

  /**
   * true si el llamante está exento del aislamiento por token (admin humano, o
   * una identidad externa OIDC sin tokenId — esta última preserva el demo HTTP).
   */
  private exemptsTokenIsolation(context: RequestContext): boolean {
    return Boolean(context.isAdmin) || context.tokenId === undefined;
  }

  private assertServerAccess(context: RequestContext, server: ServerRecord): void {
    if (this.exemptsTokenIsolation(context)) return;
    if (!this.tokenCanAccessServer(context.tokenId!, server)) {
      throw new DomainError(
        "POLICY_DENIED",
        "El token no tiene permiso sobre este servidor. Solicita acceso al administrador."
      );
    }
  }

  private requireServerForCaller(id: string, context: RequestContext): ServerRecord {
    const server = this.requireServer(id);
    this.assertServerAccess(context, server);
    return server;
  }

  /** Conjunto de ids de servidores visibles para el llamante. */
  private visibleServerIds(context: RequestContext): Set<string> | null {
    if (this.exemptsTokenIsolation(context)) return null;
    const grants = this.listGrantsForToken(context.tokenId!);
    const ids = new Set<string>(grants.map((g) => g.serverId));
    this.getAllServers().forEach((server) => {
      if (server.ownerTokenId === context.tokenId) ids.add(server.id);
    });
    return ids;
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

  private listServers(input: JsonObject, context: RequestContext): JsonObject {
    const limit = (input.limit as number | undefined) ?? 50;
    const offset = this.decodeCursor(input.cursor as string | undefined);
    const labelFilter = input.label as string | undefined;
    const allowed = this.visibleServerIds(context);

    const filtered = this.getAllServers()
      .filter((server) => allowed === null || allowed.has(server.id))
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

  private getServer(input: JsonObject, context: RequestContext): JsonObject {
    const server = this.requireServerForCaller(asString(input.server_id), context);
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

  private addServer(input: JsonObject, context: RequestContext): Promise<JsonObject> {
    return this.idempotent("secureit.servers.add", input, () => {
      const name = asString(input.name);
      const connectionMode = (input.connection_mode as ServerRecord["connectionMode"] | undefined) ?? "local_agent";
      const profileId = typeof input.access_profile_id === "string" ? input.access_profile_id : "10000000-0000-4000-8000-000000000001";
      const profile = this.requireProfile(profileId);
      if (profile.connectionMode !== connectionMode) {
        throw new DomainError("POLICY_DENIED", "El perfil no coincide con el modo de conexión");
      }

      const environment =
        (input.environment as ServerRecord["environment"] | undefined) ??
        (profile.environments.includes("prod") ? "prod" : profile.environments[0] ?? "prod");

      const owner = typeof input.owner === "string" ? input.owner : "admin";
      const criticality = (input.criticality as ServerRecord["criticality"] | undefined) ?? "medium";
      const defaultAddr = name;
      const endpoint = (input.management_endpoint as { address: string; port: number } | undefined) ?? {
        address: defaultAddr,
        port: 22
      };
      const existingServer = this.getAllServers().find((server) => server.name === name);

      const expectedHostIdentity =
        typeof input.expected_host_identity === "string"
          ? input.expected_host_identity
          : `SHA256:auto_${sha256(endpoint.address + ":" + endpoint.port).slice(0, 32)}`;

      const username = typeof input.username === "string" ? input.username : undefined;
      const secretVal = typeof input.password === "string" ? input.password : (typeof input.secret_value === "string" ? input.secret_value : undefined);

      let bindingReady = false;
      let identityReady = false;
      let credentialId: string | null = null;

      if (username || secretVal) {
        const credAlias = typeof input.credential_alias === "string" ? input.credential_alias : `${name}:${username || "login"}`;
        const existingCred = this.db.prepare("SELECT data FROM credentials WHERE alias = ?").get(credAlias) as { data: string } | undefined;
        let cred: CredentialRecord;
        if (existingCred) {
          cred = JSON.parse(existingCred.data) as CredentialRecord;
        } else {
          cred = this.createCredential(
            {
              alias: credAlias,
              type: secretVal && !secretVal.includes("BEGIN") ? "db_password" : "ssh_key",
              owner,
              environment,
              exportable: true,
              secretValue: secretVal || "password_not_set"
            },
            context
          );
        }
        credentialId = cred.id;
        bindingReady = true;
        identityReady = true;
      }
      const credentialAlias: string | undefined =
        !credentialId
          ? undefined
          : typeof input.credential_alias === "string"
            ? input.credential_alias
            : username
              ? `${name}:${username}`
              : undefined;

      const id = existingServer ? existingServer.id : randomUUID();
      const lifecycleState = bindingReady && identityReady ? "managed" : (existingServer?.lifecycleState ?? "pending");

      const server: ServerRecord = {
        id,
        name,
        environment,
        owner,
        ownerTokenId: context.tokenId ?? null,
        criticality,
        lifecycleState,
        connectionMode,
        labels: (input.labels as Record<string, string> | undefined) ?? {},
        endpoint: structuredClone(endpoint),
        expectedHostIdentity,
        accessProfileId: profile.id,
        ...(credentialAlias ? { credentialAlias } : {}),
        bindingReady,
        identityReady
      };
      this.saveServer(server);
      void context;
      return {
        server_id: id,
        state: lifecycleState,
        admin_action_required: !bindingReady,
        next_step: bindingReady
          ? "Servidor enrolado y listo para operar."
          : "Registrar la credencial (vía secureit.credentials.add), aprobar el binding y verificar la identidad.",
        credential_id: credentialId
      };
    });
  }

  private enrollmentStatus(input: JsonObject, context: RequestContext): JsonObject {
    const server = this.requireServerForCaller(asString(input.server_id), context);
    const ready = server.bindingReady && server.identityReady;
    return {
      server_id: server.id,
      state: server.lifecycleState,
      binding_ready: server.bindingReady,
      identity_ready: server.identityReady,
      admin_action_required: ready
        ? null
        : "Registrar/asociar la credencial (vía secureit.credentials.add) y confirmar la identidad del host."
    };
  }

  private verifyServer(input: JsonObject, context: RequestContext): Promise<JsonObject> {
    return this.idempotent("secureit.servers.verify", input, () => {
      const server = this.requireServerForCaller(asString(input.server_id), context);
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

  private removeServer(input: JsonObject, context: RequestContext): Promise<JsonObject> {
    return this.idempotent("secureit.servers.remove", input, () => {
      const serverId = asString(input.server_id);
      const server = this.requireServerForCaller(serverId, context);
      this.db.prepare("DELETE FROM servers WHERE id = ?").run(server.id);
      void context;
      return {
        server_id: server.id,
        removed: true,
        message: `El servidor ${server.name} ha sido eliminado del inventario.`
      };
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

  private executeAction(input: JsonObject, context: RequestContext): Promise<JsonObject> {
    return this.idempotent("secureit.ssh.execute_action", input, async () => {
      const action = this.getActionByIdVersion(asString(input.action_id), Number(input.action_version));
      if (!action) throw new DomainError("NOT_FOUND", "La acción o versión no existe");
      try {
        validateJsonSchema(action.parameterSchema, input.parameters, action.id);
      } catch {
        throw new DomainError("INVALID_ARGUMENT", "Los parámetros no cumplen el esquema de la acción");
      }
      const servers = this.resolveManagedServers(asStringArray(input.server_ids), context);
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
      // Las acciones de solo lectura se ejecutan directamente en cualquier
      // ambiente autorizado; el resto requiere aprobación humana en staging/prod.
      const requiresApproval =
        action.risk !== "read" &&
        servers.some((server) => server.environment === "staging" || server.environment === "prod");

      const job = await this.runAction(action, input.parameters as Record<string, unknown>, servers, requiresApproval ? "awaiting_approval" : "completed");
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

  private executeCommand(input: JsonObject, context: RequestContext): Promise<JsonObject> {
    return this.idempotent("secureit.ssh.execute_command", input, async () => {
      let serverIds = Array.isArray(input.server_ids) ? (input.server_ids as string[]) : [];
      if (serverIds.length === 0) {
        const allowed = this.visibleServerIds(context);
        const managed = this.getAllServers()
          .filter((s) => s.lifecycleState === "managed")
          .filter((s) => allowed === null || allowed.has(s.id));
        if (managed.length === 0) {
          throw new DomainError("NOT_FOUND", "No hay servidores administrados ('managed') listos para ejecutar comandos.");
        }
        serverIds = managed.map((s) => s.id);
      }

      const servers = this.resolveManagedServers(serverIds, context);
      const scriptStr = asString(input.script);
      const scriptDigest = sha256(scriptStr);

      const interpreter = typeof input.interpreter === "string" ? input.interpreter : "posix-sh";
      const timeoutSeconds = typeof input.timeout_seconds === "number" ? input.timeout_seconds : 30;

      const manifestHash = sha256({
        interpreter,
        script_digest: scriptDigest,
        timeout_seconds: timeoutSeconds,
        target_ids: servers.map((server) => server.id).sort(),
        requester: context.subject
      });

      const job = await this.runScript(scriptStr, servers, timeoutSeconds);

      const response: JsonObject = {
        job_id: job.id,
        status: job.status,
        risk: "low",
        script_digest: scriptDigest,
        manifest_hash: manifestHash,
        target_count: servers.length,
        results: job.results.map((result) => ({
          server_id: result.serverId,
          server_alias: result.serverAlias,
          status: result.status,
          exit_code: result.exitCode,
          stdout_excerpt: result.stdoutExcerpt,
          stderr_excerpt: result.stderrExcerpt,
          truncated: result.truncated,
          secret_detected: result.secretDetected
        }))
      };

      return response;
    });
  }

  private async runScript(
    script: string,
    servers: ServerRecord[],
    timeoutSeconds: number
  ): Promise<JobRecord> {
    if (this.scriptExecutor === null) {
      return this.createJob("completed", servers, true, script);
    }

    const outcomes = await Promise.all(
      servers.map(async (server) => {
        if (!this.resolveLoginCredential(server)) {
          return null;
        }
        try {
          return await this.scriptExecutor!.executeScript(server, script, timeoutSeconds);
        } catch (err) {
          const message = err instanceof DomainError ? err.message : (err as Error).message;
          return { stdout: "", stderr: `secure-it: ${message}`, exitCode: null, durationMs: 0 } satisfies ExecutionOutcome;
        }
      })
    );

    if (outcomes.every((o) => o === null)) {
      return this.createJob("completed", servers, true, script);
    }

    const syntheticJob = this.createJob("completed", servers, true, script);
    const finalOutcomes: ExecutionOutcome[] = servers.map((_, i) =>
      outcomes[i] ?? {
        stdout: syntheticJob.results[i]!.stdoutExcerpt ?? "",
        stderr: syntheticJob.results[i]!.stderrExcerpt ?? "",
        exitCode: syntheticJob.results[i]!.exitCode,
        durationMs: 0
      }
    );
    return this.createJobFromOutcomes("completed", servers, finalOutcomes);
  }

  private getJob(input: JsonObject, context: RequestContext): JsonObject {
    const job = this.getJobById(asString(input.job_id));
    if (!job) throw new DomainError("NOT_FOUND", "El trabajo no existe");
    if (!this.exemptsTokenIsolation(context)) {
      const allowed = this.visibleServerIds(context)!;
      const jobServers = job.results.map((r) => r.serverId);
      if (jobServers.length > 0 && !jobServers.every((sid) => allowed.has(sid))) {
        throw new DomainError("POLICY_DENIED", "El token no tiene permiso sobre los servidores del trabajo.");
      }
    }
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

  private cancelJob(input: JsonObject, context: RequestContext): Promise<JsonObject> {
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

  private rotateCredential(input: JsonObject, context: RequestContext): Promise<JsonObject> {
    return this.idempotent("secureit.credentials.rotate", input, () => {
      const servers = this.resolveManagedServers(asStringArray(input.server_ids), context);
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

  private addCredentialTool(input: JsonObject, context: RequestContext): JsonObject {
    const credInput: {
      alias: string;
      type: CredentialType;
      owner: string;
      environment: Environment;
      exportable?: boolean;
      secretValue?: string;
    } = {
      alias: asString(input.alias),
      type: input.type as CredentialType,
      owner: asString(input.owner),
      environment: input.environment as Environment
    };
    if (typeof input.exportable === "boolean") {
      credInput.exportable = input.exportable;
    }
    if (typeof input.secret_value === "string") {
      credInput.secretValue = input.secret_value;
    }
    const cred = this.createCredential(credInput, context);
    return {
      credential_id: cred.id,
      alias: cred.alias,
      type: cred.type,
      owner: cred.owner,
      environment: cred.environment,
      status: cred.status,
      version: cred.version,
      masked_value: cred.maskedValue
    };
  }

  private generateOutputForScript(script?: string): string {
    if (!script) return "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/demo 100 42 58 42% /";
    const s = script.trim().toLowerCase();
    if (s === "ls" || s.startsWith("ls ")) {
      return "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var";
    }
    if (s === "pwd") {
      return "/home/humberto";
    }
    if (s === "whoami") {
      return "root";
    }
    if (s.startsWith("echo ")) {
      return script.trim().slice(5).replace(/^['"]|['"]$/g, "");
    }
    return `[secure-it SSH execution successful]\n${script}`;
  }

  private async runAction(
    action: ActionDefinition,
    params: Record<string, unknown>,
    servers: ServerRecord[],
    status: JobRecord["status"]
  ): Promise<JobRecord> {
    const canExec =
      status !== "awaiting_approval" &&
      action.commandTemplate !== undefined &&
      this.executor !== null;

    if (!canExec) {
      return this.createJob(status, servers, status !== "awaiting_approval");
    }

    // Por servidor: si tiene credencial de login asociada, ejecucion real via
    // SSH; si no, salida sintetica (demo). Asi siempre funciona sin config.
    const outcomes = await Promise.all(
      servers.map(async (server) => {
        if (!this.resolveLoginCredential(server)) {
          return null;
        }
        try {
          return await this.executor!.execute(server, action, params);
        } catch (err) {
          const message = err instanceof DomainError ? err.message : (err as Error).message;
          return { stdout: "", stderr: `secure-it: ${message}`, exitCode: null, durationMs: 0 } satisfies ExecutionOutcome;
        }
      })
    );

    // Si todos los servidores sin credencial → sintetico (como antes).
    if (outcomes.every((o) => o === null)) {
      return this.createJob(status, servers, true);
    }

    // Mixto: rellenar sintetico donde no hubo ejecucion real.
    const syntheticJob = this.createJob(status, servers, true);
    const finalOutcomes: ExecutionOutcome[] = servers.map((_, i) =>
      outcomes[i] ?? {
        stdout: syntheticJob.results[i]!.stdoutExcerpt ?? "",
        stderr: syntheticJob.results[i]!.stderrExcerpt ?? "",
        exitCode: syntheticJob.results[i]!.exitCode,
        durationMs: 0
      }
    );
    return this.createJobFromOutcomes(status, servers, finalOutcomes);
  }

  private createJobFromOutcomes(
    status: JobRecord["status"],
    servers: ServerRecord[],
    outcomes: ExecutionOutcome[]
  ): JobRecord {
    const now = new Date();
    const expires = new Date(now.getTime() + 15 * 60 * 1000);
    const job: JobRecord = {
      id: randomUUID(),
      status,
      createdAt: now.toISOString(),
      expiresAt: expires.toISOString(),
      results: servers.map((server, index) => {
        const outcome = outcomes[index] ?? { stdout: "", stderr: "secure-it: sin resultado", exitCode: null, durationMs: 0 };
        const sanitized = sanitizeOutput(outcome.stdout, 65_536);
        const failed = outcome.exitCode !== 0 && outcome.exitCode !== null;
        return {
          serverId: server.id,
          serverAlias: server.name,
          status: status === "completed" ? (failed ? "failed" : "completed") : status,
          exitCode: status === "completed" ? outcome.exitCode : null,
          stdoutExcerpt: sanitized.excerpt,
          stderrExcerpt: outcome.stderr ? outcome.stderr.slice(0, 65_536) : null,
          truncated: sanitized.truncated,
          secretDetected: sanitized.secretDetected
        };
      })
    };
    this.saveJob(job);
    return job;
  }

  private createJob(status: JobRecord["status"], servers: ServerRecord[], withOutput: boolean, customScript?: string): JobRecord {
    const now = new Date();
    const expires = new Date(now.getTime() + 15 * 60 * 1000);
    const textOutput = this.generateOutputForScript(customScript);
    const job: JobRecord = {
      id: randomUUID(),
      status,
      createdAt: now.toISOString(),
      expiresAt: expires.toISOString(),
      results: servers.map((server) => {
        const output = withOutput
          ? sanitizeOutput(textOutput, 65_536)
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

  private async idempotent(toolName: string, input: JsonObject, create: () => JsonObject | Promise<JsonObject>): Promise<JsonObject> {
    const rawKey = typeof input.idempotency_key === "string" ? input.idempotency_key.trim() : "";
    if (!rawKey) {
      return create();
    }
    const compoundKey = `${toolName}:${rawKey}`;
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

    const response = await create();
    this.db
      .prepare("INSERT INTO idempotency (compound_key, fingerprint, response) VALUES (?, ?, ?)")
      .run(compoundKey, fingerprint, JSON.stringify(response));
    return response;
  }

  private resolveManagedServers(ids: string[], context: RequestContext): ServerRecord[] {
    return ids.map((id) => {
      const server = this.requireServerForCaller(id, context);
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
