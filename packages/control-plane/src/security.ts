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

/**
 * Patrones de script destructivos/peligrosos que fuerzan `awaiting_approval`
 * en `execute_command` (que permanece sintético + gated: el agente nunca
 * recibe shell crudo del objetivo). Endurecido frente al catálogo original:
 * - borrados recursivos, formatos y escritura a bloque de dispositivo
 * - dobles espacios que pretendían evadir `rm -rf` y variantes `--recursive`
 * - fork bombs, chmod/chown recursivos, vaciado de archivos críticos
 * - piping http a un shell de ejecución
 */
export const HIGH_RISK_SCRIPT = new RegExp(
  [
    // rm/rsync recursivos/forzados con o sin sudo, tolerando espacios extra
    String.raw`(?:^|[\s;&|])+(?:sudo\s+)?(?:(?:rm|rsync)\s+(?:-[A-Za-z]*r[A-Za-z]*\s+)?-[A-Za-z]*f)`,
    // destrucción de dispositivo / sistema de ficheros / arrancada
    String.raw`(?:^|[\s;&|])+(?:sudo\s+)?(?:mkfs[.\w]*\s|dd\s+if=\S*|dd\s+of=\S*|(?::\(\)\s*\{\s*:\|:\s*&\s*\};?)|(?:shutdown|reboot|init\s+0|halt|poweroff)\b)`,
    // permisos/propiedad recursivos o vaciado de archivos críticos
    String.raw`(?:^|[\s;&|])+(?:sudo\s+)?(?:chmod\s+-R\b|chown\s+-R\b|>\s*/dev/(?:sd|nvme|vd)[A-Za-z0-9]*|>\s*/etc/(?:passwd|shadow|sudoers))`,
    // piping de descargas a un shell de ejecución
    String.raw`(?:^|[\s;&|])(?:curl|wget)\b[^|]*\|\s*(?:sh|bash)\b`
  ].join("|"),
  "i"
);

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
