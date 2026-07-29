import type { Request, Response, NextFunction } from "express";
import { randomBytes } from "node:crypto";
import type { RequestContext } from "@secure-it/control-plane";

let cachedToken: string | null = null;

export function getAdminToken(): string {
  if (process.env.ADMIN_TOKEN) {
    return process.env.ADMIN_TOKEN;
  }
  if (!cachedToken) {
    cachedToken = "secureit-admin-token-" + randomBytes(8).toString("hex");
    console.warn(`[admin-security] Generado token efímero de administración: ${cachedToken}`);
  }
  return cachedToken;
}

export function requireAdminAuth(req: Request, res: Response, next: NextFunction): void {
  // CRITICAL SECURITY RULE: Reject any MCP identities or MCP payloads
  if (
    req.headers["x-mcp-token"] ||
    req.headers["x-mcp-session"] ||
    (typeof req.headers.authorization === "string" && req.headers.authorization.toLowerCase().includes("mcp"))
  ) {
    res.status(403).json({
      error: "POLICY_DENIED",
      message: "Las identidades y sesiones MCP tienen prohibido el acceso a la consola administrativa de credenciales."
    });
    return;
  }

  const expectedToken = getAdminToken();
  const providedToken = req.headers["x-admin-token"] || req.query.token;

  if (!providedToken || providedToken !== expectedToken) {
    res.status(401).json({
      error: "UNAUTHORIZED",
      message: "Se requiere un token de administración válido en el encabezado X-Admin-Token"
    });
    return;
  }

  (req as Request & { adminContext?: RequestContext }).adminContext = {
    subject: "operator:human_admin",
    scopes: new Set(["credential:admin", "audit:read", "secureit:servers:read", "secureit:servers:write"])
  };

  next();
}
