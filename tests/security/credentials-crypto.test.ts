import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { unlinkSync, existsSync, statSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { SqliteControlPlane, encryptSecret, decryptSecret } from "@secure-it/control-plane";
import type { RequestContext } from "../../packages/control-plane/src/types.js";

const adminCtx: RequestContext = { subject: "admin-test", scopes: new Set() };

function rawCredRows(db: DatabaseSync): Array<{ id: string; data: string }> {
  return db.prepare("SELECT id, data FROM credentials").all() as Array<{ id: string; data: string }>;
}

describe("cifrado de credenciales en reposo (AES-256-GCM)", () => {
  it("primitivas: cifra a un payload versionado distinto del plano y descifra al original", () => {
    const mk = { key: Buffer.alloc(32, 7), ephemeral: false } as never;
    const ct = encryptSecret("hunter2", mk, true);
    expect(ct).toMatch(/^v1\./);
    expect(ct).not.toContain("hunter2");
    expect(decryptSecret(ct, mk)).toBe("hunter2");
  });

  it("detecta alteración del ciphertext (auth tag inválido)", () => {
    const mk = { key: Buffer.alloc(32, 7), ephemeral: false } as never;
    const ct = encryptSecret("secreto", mk, true);
    const tampered = ct.slice(0, -4) + "AAAA";
    expect(() => decryptSecret(tampered, mk)).toThrow();
  });

  it("persiste secretCipher en la DB y NUNCA el secretValue en claro", () => {
    const cp = new SqliteControlPlane({ inMemory: true, seedDemoData: true });
    const rows = rawCredRows(cp["db"]);
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const cred = JSON.parse(row.data);
      expect(typeof cred.secretCipher).toBe("string");
      expect(cred.secretCipher.startsWith("v1.")).toBe(true);
      expect(cred.secretValue).toBeUndefined();
      // El plaintext conocido de los fixtures no debe aparecer en disco
      expect(row.data).not.toContain("s3cur3_Stag!ng_P@ssw0rd_2026");
      expect(row.data).not.toContain("PROTECTED_NON_EXPORTABLE_CA_KEY");
    }
    cp.close();
  });

  it("revela el secreto original descifrándolo desde secretCipher", () => {
    const cp = new SqliteControlPlane({ inMemory: true, seedDemoData: true });
    const list = cp.listCredentials();
    const exportable = list.find((c) => c.exportable && c.alias === "postgres-staging-rw")!;
    const revealed = cp.revealCredential(exportable.id, adminCtx, "auditoría");
    expect(revealed).toBe("s3cur3_Stag!ng_P@ssw0rd_2026");
    cp.close();
  });

  it("listCredentials omite secretValue y secretCipher (solo maskedValue)", () => {
    const cp = new SqliteControlPlane({ inMemory: true, seedDemoData: true });
    for (const cred of cp.listCredentials()) {
      expect(cred.secretValue).toBeUndefined();
      expect(cred.secretCipher).toBeUndefined();
      expect(cred.maskedValue).toBe("••••••••");
    }
    cp.close();
  });

  it("rotación reemplaza el ciphertext con uno nuevo", () => {
    const cp = new SqliteControlPlane({ inMemory: true, seedDemoData: true });
    const before = rawCredRows(cp["db"])[0]!;
    const after = cp.rotateCredentialAdmin(before.id, adminCtx);
    expect(after.version).toBeGreaterThan(1);
    const stored = rawCredRows(cp["db"]).find((r) => r.id === before.id)!;
    const beforeCred = JSON.parse(before.data);
    const afterCred = JSON.parse(stored.data);
    expect(afterCred.secretCipher).not.toBe(beforeCred.secretCipher);
    cp.close();
  });

  it("migra filas legacy en claro a ciphertext al aportar SECUREIT_MASTER_KEY", () => {
    const dbPath = join(tmpdir(), `test-secureit-migrate-${randomUUID()}.db`);
    const masterKey = "test-master-passphrase-very-long";
    try {
      // 1) Construye a mano una DB legacy con credenciales en claro (pre-fix)
      const raw = new DatabaseSync(dbPath);
      raw.exec(`
        CREATE TABLE credentials (id TEXT PRIMARY KEY, alias TEXT UNIQUE NOT NULL, data TEXT NOT NULL);
        CREATE TABLE servers (id TEXT PRIMARY KEY, name TEXT UNIQUE, data TEXT NOT NULL);
        CREATE TABLE profiles (id TEXT PRIMARY KEY, name TEXT UNIQUE, data TEXT NOT NULL);
        CREATE TABLE actions (id_version TEXT PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE jobs (id TEXT PRIMARY KEY, status TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE idempotency (compound_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, response TEXT NOT NULL);
        CREATE TABLE audit_events (id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, data TEXT NOT NULL);
      `);
      const legacyCred = {
        id: "cred-legacy-db",
        alias: "postgres-staging-rw",
        type: "db_password",
        owner: "backend",
        environment: "staging",
        status: "active",
        version: 1,
        lastRotatedAt: new Date().toISOString(),
        expiresAt: null,
        exportable: true,
        maskedValue: "••••••••",
        secretValue: "s3cur3_Stag!ng_P@ssw0rd_2026"
      };
      raw.prepare("INSERT INTO credentials (id, alias, data) VALUES (?, ?, ?)").run(
        legacyCred.id, legacyCred.alias, JSON.stringify(legacyCred)
      );
      raw.close();

      // 2) Reabre vía SqliteControlPlane CON clave: la migración cifra las filas legacy
      const cp = new SqliteControlPlane({ dbPath, masterKey, adminPassword: "test-bootstrap-password" });
      const migratedRow = rawCredRows(cp["db"]).find((r) => JSON.parse(r.data).alias === "postgres-staging-rw")!;
      const migrated = JSON.parse(migratedRow.data);
      expect(migrated.secretCipher.startsWith("v1.")).toBe(true);
      expect(migrated.secretValue).toBeUndefined();
      expect(cp.revealCredential(migrated.id, adminCtx, "post-migración")).toBe("s3cur3_Stag!ng_P@ssw0rd_2026");
      cp.close();
    } finally {
      if (existsSync(dbPath)) unlinkSync(dbPath);
    }
  });

  it("genera una clave local protegida si SECUREIT_MASTER_KEY no está definida", () => {
    const dbPath = join(tmpdir(), `test-secureit-nokey-${randomUUID()}.db`);
    try {
      const cp = new SqliteControlPlane({ dbPath, adminPassword: "test-bootstrap-password" });
      expect(() => cp.createCredential({ alias: "x", secretValue: "nueva" }, adminCtx)).not.toThrow();
      expect(existsSync(`${dbPath}.key`)).toBe(true);
      expect(statSync(`${dbPath}.key`).mode & 0o777).toBe(0o600);
      cp.close();
    } finally {
      if (existsSync(dbPath)) unlinkSync(dbPath);
      if (existsSync(`${dbPath}.key`)) unlinkSync(`${dbPath}.key`);
    }
  });
});
