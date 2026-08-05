import { randomBytes, createHash } from "node:crypto";

export const TOKEN_PREFIX = "sit_";

export function generateTokenRaw(): string {
  return TOKEN_PREFIX + randomBytes(24).toString("base64url");
}

export function isInternalToken(value: string): boolean {
  return typeof value === "string" && value.startsWith(TOKEN_PREFIX);
}

export function hashToken(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}