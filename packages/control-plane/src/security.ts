import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { DomainError } from "./errors.js";

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, canonicalize(child)])
    );
  }
  return value;
}

export function sha256(value: unknown): string {
  const serialized = typeof value === "string" ? value : JSON.stringify(canonicalize(value));
  return `sha256:${createHash("sha256").update(serialized).digest("hex")}`;
}

export function assertSafeDemoEndpoint(address: string, port: number): void {
  const normalized = address.toLowerCase().replace(/\.$/, "");
  if (port < 1 || port > 65535) {
    throw new DomainError("INVALID_ARGUMENT", "Puerto de conexión inválido");
  }

  // Reject dangerous SSRF targets (loopback, metadata endpoints, 10.0.0.0/8)
  if (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "0.0.0.0" ||
    normalized === "::1" ||
    normalized === "169.254.169.254" ||
    normalized.includes("metadata")
  ) {
    throw new DomainError("POLICY_DENIED", "No se permite registrar endpoints de loopback o metadata local.");
  }

  if (isIP(normalized) === 4) {
    const octets = normalized.split(".").map(Number);
    if (octets[0] === 10) {
      throw new DomainError("POLICY_DENIED", "No se permite el acceso a la red privada interna 10.0.0.0/8");
    }
  }
}

const suspiciousOutputPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  /\b(?:password|passwd|secret|token)\s*[:=]\s*\S+/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/
];

export function sanitizeOutput(output: string, maxBytes: number): {
  excerpt: string | null;
  truncated: boolean;
  secretDetected: boolean;
} {
  const cleaned = output.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
  if (suspiciousOutputPatterns.some((pattern) => pattern.test(cleaned))) {
    return { excerpt: null, truncated: false, secretDetected: true };
  }

  const bytes = Buffer.from(cleaned, "utf8");
  if (bytes.length <= maxBytes) {
    return { excerpt: cleaned, truncated: false, secretDetected: false };
  }

  return {
    excerpt: bytes.subarray(0, maxBytes).toString("utf8"),
    truncated: true,
    secretDetected: false
  };
}
