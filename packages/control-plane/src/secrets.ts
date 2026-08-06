import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  type CipherKey
} from "node:crypto";
import { DomainError } from "./errors.js";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";

/**
 * Forma persistida del secreto: `v1.<base64(iv)>.<base64(tag)>.<base64(ciphertext)>`.
 * El prefijo de versión permite evolucionar el esquema (p. ej. a XChaCha20-Poly1305
 * o rotación de KDF) sin reescribir lectores legacy.
 */
const CIPHER_VERSION = "v1";
const CIPHER_TAG = `${CIPHER_VERSION}.`;
const IV_BYTES = 12;
const KEY_BYTES = 32;

export interface MasterKey {
  key: CipherKey;
  ephemeral: boolean;
}

export interface ResolveMasterKeyOptions {
  masterKey?: string | Buffer;
  inMemory?: boolean;
  keyFile?: string;
}

const scryptSalt = Buffer.from("secure-it/aes-256-gcm/v1", "utf8");

function deriveKey(material: string): CipherKey {
  // scrypt normaliza cualquier passphrase (hex, base64, frase) a 32 bytes.
  return scryptSync(material, scryptSalt, KEY_BYTES, {
    N: 2 ** 14,
    r: 8,
    p: 1,
    maxmem: 48 * 1024 * 1024
  });
}

/**
 * Resuelve la clave maestra de cifrado de credenciales en reposo.
 *
 * Orden de precedencia:
 *   1. `options.masterKey` (inyección directa, p. ej. para tests)
 *   2. `process.env.SECUREIT_MASTER_KEY` (passphrase hex/base64/frase)
 *   3. Clave efímera aleatoria (solo aceptable en `:memory:`; persistir con ella
 *      haría las credenciales ilegibles tras un reinicio, por lo que el cifrado
 *      hacia una DB en disco se bloquea con `DomainError` en `encryptSecret`).
 */
export function resolveMasterKey(options: ResolveMasterKeyOptions = {}): MasterKey {
  const explicit = options.masterKey ?? process.env.SECUREIT_MASTER_KEY;
  if (explicit) {
    return { key: deriveKey(String(explicit)), ephemeral: false };
  }
  if (!options.inMemory && options.keyFile) {
    let material: string;
    try {
      material = readFileSync(options.keyFile, "utf8").trim();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") throw error;
      material = randomBytes(KEY_BYTES).toString("base64url");
      writeFileSync(options.keyFile, `${material}\n`, { mode: 0o600, flag: "wx" });
    }
    chmodSync(options.keyFile, 0o600);
    return { key: deriveKey(material), ephemeral: false };
  }
  return { key: randomBytes(KEY_BYTES), ephemeral: true };
}

function requirePersistableKey(master: MasterKey, inMemory: boolean): void {
  if (master.ephemeral && !inMemory) {
    throw new DomainError(
      "INVALID_ARGUMENT",
      "SECUREIT_MASTER_KEY es obligatoria para cifrar credenciales en una base de datos en disco. " +
        "Define la variable de entorno SECUREIT_MASTER_KEY (frase, hex o base64) antes de iniciar el plano de control."
    );
  }
}

function splitPayload(payload: string): { iv: Buffer; tag: Buffer; ct: Buffer } {
  const parts = payload.split(".");
  if (parts.length !== 4 || parts[0] !== CIPHER_VERSION) {
    throw new DomainError("INVALID_STATE", "Secreto cifrado con versión/formato desconocido");
  }
  const iv = Buffer.from(parts[1] ?? "", "base64");
  const tag = Buffer.from(parts[2] ?? "", "base64");
  const ct = Buffer.from(parts[3] ?? "", "base64");
  if (iv.length !== IV_BYTES || tag.length !== 16) {
    throw new DomainError("INVALID_STATE", "Secreto cifrado corrupto");
  }
  return { iv, tag, ct };
}

export function encryptSecret(plaintext: string, master: MasterKey, inMemory: boolean): string {
  requirePersistableKey(master, inMemory);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", master.key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [CIPHER_VERSION, iv.toString("base64"), tag.toString("base64"), ct.toString("base64")].join(".");
}

export function decryptSecret(payload: string, master: MasterKey): string {
  let parsed: { iv: Buffer; tag: Buffer; ct: Buffer };
  try {
    parsed = splitPayload(payload);
  } catch {
    throw new DomainError("INVALID_STATE", "Secreto cifrado corrupto o ilegible");
  }
  const decipher = createDecipheriv("aes-256-gcm", master.key, parsed.iv);
  decipher.setAuthTag(parsed.tag);
  try {
    return Buffer.concat([decipher.update(parsed.ct), decipher.final()]).toString("utf8");
  } catch {
    throw new DomainError(
      "INVALID_STATE",
      "No se pudo descifrar el secreto: la clave maestra (SECUREIT_MASTER_KEY) no coincide o el dato fue alterado."
    );
  }
}

export function isEncryptedPayload(value: string): boolean {
  return value.startsWith(CIPHER_TAG) && value.split(".").length === 4;
}
