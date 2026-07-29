import express, { type Request, type Response } from "express";
import { join } from "node:path";
import { SqliteControlPlane, DomainError, type RequestContext } from "@secure-it/control-plane";
import { getAdminToken, requireAdminAuth } from "./auth.js";

export { getAdminToken };

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

  // Security Headers Middleware (Mandatory Secure Web Skills)
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'self'"
    );
    next();
  });

  // Health check
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", service: "secure-it-admin" });
  });

  // Auth Status check for UI
  app.get("/api/auth/token", (_req, res) => {
    res.json({ token: getAdminToken() });
  });

  // Protected REST API routes
  app.use("/api", requireAdminAuth);

  app.get("/api/credentials", (_req: Request, res: Response) => {
    const list = controlPlane.listCredentials();
    res.json(list);
  });

  app.get("/api/servers", async (req: Request, res: Response) => {
    try {
      const context = (req as Request & { adminContext?: RequestContext }).adminContext!;
      const result = await controlPlane.call("secureit.servers.list", {}, context);
      res.json(result);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/servers", async (req: Request, res: Response) => {
    try {
      const context = (req as Request & { adminContext?: RequestContext }).adminContext!;
      const result = await controlPlane.call("secureit.servers.add", req.body, context);
      res.status(201).json(result);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.delete("/api/servers/:id", async (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = (req as Request & { adminContext?: RequestContext }).adminContext!;
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
      const context = (req as Request & { adminContext?: RequestContext }).adminContext!;
      const cred = controlPlane.createCredential(req.body, context);
      res.status(201).json(cred);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/credentials/:id/reveal", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = (req as Request & { adminContext?: RequestContext }).adminContext!;
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
      const context = (req as Request & { adminContext?: RequestContext }).adminContext!;
      const cred = controlPlane.rotateCredentialAdmin(id, context);
      res.json(cred);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/credentials/:id/revoke", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = (req as Request & { adminContext?: RequestContext }).adminContext!;
      const cred = controlPlane.revokeCredentialAdmin(id, context);
      res.json(cred);
    } catch (err) {
      handleError(res, err);
    }
  });

  app.post("/api/credentials/:id/test", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const context = (req as Request & { adminContext?: RequestContext }).adminContext!;
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

  // Serve Static Frontend Assets
  const publicDir = join(import.meta.dirname, "..", "public");
  app.use(express.static(publicDir));

  return { app, controlPlane };
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
