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
  const allowedPort = port === 22 || port === 443 || port === 8443;
  if (!allowedPort) {
    throw new DomainError("POLICY_DENIED", "El puerto no está permitido por la política demo");
  }

  if (normalized === "example.com" || normalized.endsWith(".example")) return;

  if (isIP(normalized) === 4) {
    const octets = normalized.split(".").map(Number);
    const allowed =
      (octets[0] === 192 && octets[1] === 0 && octets[2] === 2) ||
      (octets[0] === 198 && octets[1] === 51 && octets[2] === 100) ||
      (octets[0] === 203 && octets[1] === 0 && octets[2] === 113);
    if (allowed) return;
  }

  throw new DomainError(
    "POLICY_DENIED",
    "El modo demo solo admite dominios .example y rangos IP reservados para documentación"
  );
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
