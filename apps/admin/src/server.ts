import express, { type Request, type Response } from "express";
import { join } from "node:path";
import { SqliteControlPlane, DomainError, type RequestContext, type TokenRecord, type TokenServerGrant } from "@secure-it/control-plane";
import { createSession, destroySession, requireAdminAuth } from "./auth.js";

export interface CreateAdminServerOptions {
  controlPlane?: SqliteControlPlane;
  dbPath?: string;
}

export function createAdminServer(options: CreateAdminServerOptions = {}) {
  const app = express();
  const controlPlane =
    options.controlPlane ||
    new SqliteControlPlane(options.dbPath ? { dbPath: options.dbPath } : {});

  app.use(express.json());

  app.disable("x-powered-by");

  // Security Headers
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; object-src 'none'; frame-ancestors 'self'"
    );
    next();
  });

  // Health check (sin auth)
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", service: "secure-it-admin" });
  });

  // ── Auth: login / sesión / cambio de contraseña ──────────────────────
  app.post("/api/auth/login", (req: Request, res: Response) => {
    const username = typeof req.body?.username === "string" ? req.body.username.trim() : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!username || !password) {
      res.status(400).json({ error: "INVALID_ARGUMENT", message: "Se requieren usuario y contraseña" });
      return;
    }
    const user = controlPlane.verifyAdminLogin(username, password);
    if (!user) {
      res.status(401).json({ error: "UNAUTHORIZED", message: "Usuario o contraseña incorrectos" });
      return;
    }
    const sessionToken = createSession(user.username);
    res.json({ session_token: sessionToken, username: user.username });
  });

  app.post("/api/auth/logout", (req: Request, res: Response) => {
    const token = (req.headers["x-admin-token"] as string) || extractBearer(req);
    destroySession(token);
    res.json({ ok: true });
  });

  // A partir de aquí, todo requiere sesión admin válida.
  app.use("/api", requireAdminAuth);

  app.post("/api/auth/change-password", (req: Request, res: Response) => {
    const ctx = adminContextOf(req);
    if (!ctx) { res.status(401).json({ error: "UNAUTHORIZED", message: "No autenticado" }); return; }
    const current = typeof req.body?.current_password === "string" ? req.body.current_password : "";
    const next = typeof req.body?.new_password === "string" ? req.body.new_password : "";
    if (!current || !next || next.length < 4) {
      res.status(400).json({ error: "INVALID_ARGUMENT", message: "Contraseña nueva demasiado corta (mín. 4)" });
      return;
    }
    const ok = controlPlane.changeAdminPassword(ctx.adminUser, current, next);
    if (!ok) {
      res.status(401).json({ error: "UNAUTHORIZED", message: "La contraseña actual no es correcta" });
      return;
    }
    res.json({ ok: true });
  });

  // Quién soy
  app.get("/api/auth/me", (req: Request, res: Response) => {
    const ctx = adminContextOf(req);
    res.json({ username: ctx?.adminUser ?? "bootstrap", isAdmin: true });
  });

  // ── Inventario & credenciales (existentes) ───────────────────────────
  app.get("/api/credentials", (_req: Request, res: Response) => {
    const list = controlPlane.listCredentials();
    res.json(list);
  });

  app.get("/api/servers", (_req: Request, res: Response) => {
    const servers = controlPlane.listServersForAdmin();
    res.json({ servers });
  });

  app.post("/api/servers", async (req: Request, res: Response) => {
    try {
      const context = adminContextOf(req)!.ctx!;
      const result = await controlPlane.call("secureit.servers.add", req.body, context);
      res.status(201).json(result);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.delete("/api/servers/:id", async (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = adminContextOf(req)!.ctx!;
      const result = await controlPlane.call(
        "secureit.servers.remove",
        { server_id: id, reason: "Baja de servidor desde la consola web admin", idempotency_key: crypto.randomUUID() },
        context
      );
      res.json(result);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/credentials", (req: Request, res: Response) => {
    try {
      const context = adminContextOf(req)!.ctx!;
      const cred = controlPlane.createCredential(req.body, context);
      res.status(201).json(cred);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/credentials/:id/reveal", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = adminContextOf(req)!.ctx!;
      const reason = typeof req.body?.reason === "string" ? req.body.reason : undefined;
      const secret = controlPlane.revealCredential(id, context, reason);
      res.json({ id, secretValue: secret });
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/credentials/:id/rotate", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = adminContextOf(req)!.ctx!;
      const cred = controlPlane.rotateCredentialAdmin(id, context);
      res.json(cred);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/credentials/:id/revoke", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = adminContextOf(req)!.ctx!;
      const cred = controlPlane.revokeCredentialAdmin(id, context);
      res.json(cred);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/credentials/:id/test", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = adminContextOf(req)!.ctx!;
      const result = controlPlane.testCredentialAccessAdmin(id, context);
      res.json(result);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.get("/api/audit-events", (_req: Request, res: Response) => {
    const events = controlPlane.getAuditEvents();
    res.json(events);
  });

  // ── Gestión de tokens (session-tokens + token general) ────────────────
  app.get("/api/tokens", (_req: Request, res: Response) => {
    const general = controlPlane.ensureGeneralToken();
    const tokens = controlPlane.listTokens();
    const safe = tokens.map((t) => ({
      id: t.id,
      name: t.name,
      subject: t.subject,
      is_general: t.isGeneral,
      active: t.active,
      created_at: t.createdAt,
      expires_at: t.expiresAt,
      scopes: t.scopes
    }));
    res.json({
      tokens: safe,
      general_id: general.id,
      general_active: general.active
    });
  });

  app.post("/api/tokens", (req: Request, res: Response) => {
    try {
      const name = typeof req.body?.name === "string" ? req.body.name : "";
      const scopes = Array.isArray(req.body?.scopes) ? (req.body.scopes as string[]) : undefined;
      const { token, raw } = controlPlane.createToken(name, scopes);
      res.status(201).json({
        token: sanitizeToken(token),
        raw_token: raw,
        note: "Guarda este valor ahora; no se volverá a mostrar."
      });
    } catch (err) {
      handleError(res, err);
    }
  });

  app.patch("/api/tokens/:id", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const active = req.body?.active === true;
      const token = controlPlane.getTokenById(id);
      if (!token) {
        res.status(404).json({ error: "NOT_FOUND", message: "Token no encontrado" });
        return;
      }
      if (token.isGeneral) {
        res.status(400).json({ error: "INVALID_ARGUMENT", message: "El token general no se puede desactivar" });
        return;
      }
      controlPlane.setTokenActive(id, active);
      res.json({ ok: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  app.delete("/api/tokens/:id", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const token = controlPlane.getTokenById(id);
      if (!token) {
        res.status(404).json({ error: "NOT_FOUND", message: "Token no encontrado" });
        return;
      }
      if (token.isGeneral) {
        res.status(400).json({ error: "INVALID_ARGUMENT", message: "El token general no se puede eliminar" });
        return;
      }
      controlPlane.setTokenActive(id, false);
      res.json({ ok: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // ── Permisos: grants de token → servidor ────────────────────────────
  app.get("/api/servers/:id/grants", (req: Request, res: Response) => {
    const serverId = String(req.params.id);
    const grants = controlPlane.listGrantsForServer(serverId);
    const tokens = controlPlane.listTokens().map(sanitizeToken);
    res.json({ grants, tokens });
  });

  app.post("/api/servers/:id/grants", (req: Request, res: Response) => {
    try {
      const serverId = String(req.params.id);
      const tokenId = typeof req.body?.token_id === "string" ? req.body.token_id : "";
      const ctx = adminContextOf(req)!.ctx!;
      if (!tokenId) {
        res.status(400).json({ error: "INVALID_ARGUMENT", message: "Falta token_id" });
        return;
      }
      const grant = controlPlane.grantServerAccess(tokenId, serverId, ctx.subject);
      res.status(201).json(grant);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.delete("/api/servers/:id/grants/:tokenId", (req: Request, res: Response) => {
    const serverId = String(req.params.id);
    const tokenId = String(req.params.tokenId);
    controlPlane.revokeServerAccess(tokenId, serverId);
    res.json({ ok: true });
  });

  // Sirve la interfaz web (incluida la de login).
  const publicDir = join(import.meta.dirname, "..", "public");
  app.use(express.static(publicDir));

  return { app, controlPlane };
}

function sanitizeToken<T extends TokenRecord | TokenServerGrant>(t: T): Record<string, unknown> {
  const out: Record<string, unknown> = { ...t };
  delete (out as Partial<TokenRecord>).tokenHash;
  return out;
}

function extractBearer(req: Request): string | undefined {
  const auth = req.headers.authorization;
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    return auth.slice(7).trim();
  }
  return undefined;
}

function adminContextOf(req: Request): { ctx: RequestContext; adminUser: string } | undefined {
  const ctx = (req as Request & { adminContext?: RequestContext }).adminContext;
  const adminUser = (req as Request & { adminUser?: string }).adminUser;
  if (!ctx) return undefined;
  return { ctx, adminUser: adminUser ?? "bootstrap" };
}

function handleError(res: Response, err: unknown): void {
  if (err instanceof DomainError) {
    const statusMap: Record<string, number> = {
      NOT_FOUND: 404,
      CONFLICT: 409,
      POLICY_DENIED: 403,
      INVALID_STATE: 400,
      INVALID_ARGUMENT: 400
    };
    res.status(statusMap[err.code] || 400).json({ error: err.code, message: err.message });
  } else {
    res.status(500).json({ error: "INTERNAL_ERROR", message: "Ocurrió un error inesperado en el servidor" });
  }
}
