import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SqliteControlPlane } from "@secure-it/control-plane";

const opened: SqliteControlPlane[] = [];

afterEach(() => {
  for (const store of opened.splice(0)) store.close();
});

describe("bootstrap administrativo", () => {
  it("permite el primer arranque y deja pendiente el alta local", () => {
    const dbPath = join(mkdtempSync(join(tmpdir(), "secure-it-bootstrap-")), "secureit.db");
    const store = new SqliteControlPlane({ dbPath, masterKey: "test-master-key" });
    opened.push(store);
    expect(store.hasAdminUsers()).toBe(false);
    store.createInitialAdmin("admin", "a-long-random-password");
    expect(store.hasAdminUsers()).toBe(true);
  });

  it("crea la cuenta inicial sin exponer la contraseña", () => {
    const dbPath = join(mkdtempSync(join(tmpdir(), "secure-it-bootstrap-")), "secureit.db");
    const store = new SqliteControlPlane({
      dbPath,
      masterKey: "test-master-key",
      adminUsername: "operator",
      adminPassword: "a-long-random-password"
    });
    opened.push(store);
    expect(store.verifyAdminLogin("operator", "a-long-random-password")?.username).toBe("operator");
    expect(store.verifyAdminLogin("operator", "admin")).toBeNull();
  });
});
