import type { Request, Response, NextFunction } from "express";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { RequestContext, SqliteControlPlane } from "@secure-it/control-plane";

interface AdminSession {
  username: string;
  createdAt: number;
}

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const sessions = new Map<string, AdminSession>();

function tokenEquals(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

export function createSession(username: string): string {
  const token = "ses_" + randomBytes(24).toString("base64url");
  sessions.set(token, { username, createdAt: Date.now() });
  return token;
}

export function destroySession(token: string | undefined): void {
  if (token && sessions.has(token)) sessions.delete(token);
}

export function resolveSession(token: string | undefined): AdminSession | null {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() - session.createdAt > SESSION_TTL_MS) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function extractSessionToken(req: Request): string | undefined {
  const header = req.headers["x-admin-token"];
  if (typeof header === "string" && header.length > 0) return header;
  const auth = req.headers.authorization;
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    const candidate = auth.slice(7).trim();
    if (candidate.startsWith("ses_")) return candidate;
  }
  return undefined;
}

/**
 * Token administrativo bootstrap opcional (env `ADMIN_TOKEN`). Solo se acepta
 * como mecanismo de scripting/automatización; la consola web usa sesión login.
 */
function bootstrapAdminToken(): string | null {
  const env = process.env.ADMIN_TOKEN;
  return env && env.length > 0 ? env : null;
}

export function requireAdminAuth(req: Request, res: Response, next: NextFunction): void {
  // CRITICAL SECURITY RULE: reject any MCP identities in admin scope.
  if (
    req.headers["x-mcp-token"] ||
    req.headers["x-mcp-session"] ||
    (typeof req.headers.authorization === "string" && req.headers.authorization.toLowerCase().includes("bearer sit_"))
  ) {
    res.status(403).json({
      error: "POLICY_DENIED",
      message: "Las identidades y sesiones MCP tienen prohibido el acceso a la consola administrativa."
    });
    return;
  }

  const sessionToken = extractSessionToken(req);
  const session = resolveSession(sessionToken);
  const bootstrap = bootstrapAdminToken();

  if (session) {
    (req as Request & { adminContext?: RequestContext; adminUser?: string }).adminContext = adminContextFor(session.username);
    (req as Request & { adminUser?: string }).adminUser = session.username;
    next();
    return;
  }

  if (bootstrap && sessionToken && tokenEquals(sessionToken, bootstrap)) {
    (req as Request & { adminContext?: RequestContext }).adminContext = adminContextFor("bootstrap");
    next();
    return;
  }

  res.status(401).json({
    error: "UNAUTHORIZED",
    message: "Inicia sesión con usuario y contraseña (POST /api/auth/login)."
  });
}

function adminContextFor(username: string): RequestContext {
  return {
    subject: `operator:${username}`,
    scopes: new Set(["credential:admin", "audit:read", "secureit:servers:read", "secureit:servers:write"]),
    isAdmin: true
  };
}

export function getControlPlaneTokenEnroller(controlPlane: SqliteControlPlane): SqliteControlPlane {
  return controlPlane;
}