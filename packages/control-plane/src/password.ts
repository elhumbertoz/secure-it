import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const SCRYPT_N = 2 ** 14;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;
const SALT_LEN = 16;
const PREFIX = "scrypt$";

export function hashPassword(plaintext: string): string {
  const salt = randomBytes(SALT_LEN);
  const derived = scryptSync(plaintext, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 48 * 1024 * 1024
  });
  return `${PREFIX}${salt.toString("base64")}$${derived.toString("base64")}`;
}

export function verifyPassword(plaintext: string, stored: string): boolean {
  if (!stored.startsWith(PREFIX)) return false;
  const rest = stored.slice(PREFIX.length);
  const sep = rest.indexOf("$");
  if (sep < 0) return false;
  const salt = Buffer.from(rest.slice(0, sep), "base64");
  const known = Buffer.from(rest.slice(sep + 1), "base64");
  if (known.length !== KEY_LEN) return false;
  const derived = scryptSync(plaintext, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 48 * 1024 * 1024
  });
  return timingSafeEqual(derived, known);
}