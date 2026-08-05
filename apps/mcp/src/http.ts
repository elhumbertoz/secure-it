import type { Server as NodeHttpServer } from "node:http";
import { allDemoScopes } from "@secure-it/contracts";
import { DemoControlPlane, isInternalToken, type TokenRecord } from "@secure-it/control-plane";
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter
} from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { hostHeaderValidation } from "@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { OAuthMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import express, {
  type ErrorRequestHandler,
  type Express,
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response
} from "express";
import { rateLimit } from "express-rate-limit";
import { OidcJwtVerifier } from "./auth.js";
import type { HttpServerConfig } from "./config.js";
import { createMcpServer, type ControlPlane, type McpIdentity } from "./server.js";

export interface HttpAppOptions {
  config: HttpServerConfig;
  verifier?: OAuthTokenVerifier;
  controlPlane?: ControlPlane;
  readinessProbe?: () => boolean | Promise<boolean>;
}

export function createHttpMcpApp(options: HttpAppOptions): Express {
  const { config } = options;
  const app = express();
  const verifier = options.verifier ?? new OidcJwtVerifier(config.oidc);
  const controlPlane = options.controlPlane ?? new DemoControlPlane();
  const knownScopes = new Set(allDemoScopes);

  app.disable("x-powered-by");
  app.set("trust proxy", false);
  app.use(hostHeaderValidation(config.allowedHosts));

  app.get("/healthz", (_request, response) => {
    response.status(200).json({ status: "ok" });
  });
  app.get("/readyz", async (_request, response) => {
    try {
      const ready = (await options.readinessProbe?.()) ?? true;
      response.status(ready ? 200 : 503).json({ status: ready ? "ready" : "not_ready" });
    } catch {
      response.status(503).json({ status: "not_ready" });
    }
  });

  const oauthMetadata: OAuthMetadata = {
    issuer: config.oidc.issuer,
    authorization_endpoint: config.authorizationUrl.href,
    token_endpoint: config.tokenUrl.href,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [...allDemoScopes]
  };
  app.use(
    mcpAuthMetadataRouter({
      oauthMetadata,
      resourceServerUrl: config.publicUrl,
      scopesSupported: [...allDemoScopes],
      resourceName: "secure-it MCP"
    })
  );

  const originProtection = allowedOrigin(config.allowedOrigins);
  const limiter = rateLimit({
    windowMs: config.rateLimitWindowMs,
    limit: config.rateLimitMax,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    handler: (_request, response) => {
      response.status(429).json({ error: "rate_limited" });
    }
  });
  const bearerAuth = requireBearerAuth({
    verifier,
    requiredScopes: [],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(config.publicUrl)
  });
  const supportedScope: RequestHandler = (request, response, next) => {
    if (request.auth?.scopes.some((scope) => knownScopes.has(scope))) {
      next();
      return;
    }
    response
      .status(403)
      .set("WWW-Authenticate", 'Bearer error="insufficient_scope"')
      .json({ error: "insufficient_scope" });
  };

  app.options("/mcp", originProtection, limiter, (_request, response) => {
    response
      .status(204)
      .set("Access-Control-Allow-Methods", "POST")
      .set(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, MCP-Protocol-Version"
      )
      .set("Access-Control-Max-Age", "600")
      .end();
  });

  // Resolución de identidad: session-token interno prioritario; si no, OIDC.
  const resolveIdentity: RequestHandler = (request, response, next) => {
    const raw = extractInternalToken(request);
    if (raw !== null) {
      const token = resolveInternalToken(controlPlane, raw);
      if (!token) {
        response.status(401).set("WWW-Authenticate", 'Bearer error="invalid_token"').json({ error: "invalid_token" });
        return;
      }
      const scopes = token.scopes.length > 0 ? new Set(token.scopes) : new Set(allDemoScopes);
      if (![...scopes].some((scope) => knownScopes.has(scope))) {
        response.status(403).set("WWW-Authenticate", 'Bearer error="insufficient_scope"').json({ error: "insufficient_scope" });
        return;
      }
      (request as Request & { mcpIdentity?: McpIdentity }).mcpIdentity = {
        subject: token.subject,
        scopes,
        tokenId: token.id
      };
      next();
      return;
    }
    // Sin token interno → verificación OIDC (respaldo HTTP) como hasta ahora.
    bearerAuth(request, response, (err: unknown) => {
      if (err) {
        next(err);
        return;
      }
      supportedScope(request, response, next);
    });
  };

  app.use("/mcp", originProtection, limiter, resolveIdentity);
  app.post(
    "/mcp",
    requireJsonContentType,
    express.json({ limit: config.requestMaxBytes, strict: true, type: "application/json" }),
    async (request, response) => {
      await handleMcpPost(request, response, controlPlane);
    }
  );
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);
  app.all("/mcp", methodNotAllowed);

  app.use((_request, response) => {
    response.status(404).json({ error: "not_found" });
  });
  app.use(safeErrorHandler);
  return app;
}

export async function listenHttpMcp(app: Express, config: HttpServerConfig): Promise<NodeHttpServer> {
  return await new Promise((resolve, reject) => {
    const server = app.listen(config.port, config.host, () => resolve(server));
    server.once("error", reject);
  });
}

async function handleMcpPost(
  request: Request,
  response: Response,
  controlPlane: ControlPlane
): Promise<void> {
  const internalIdentity = (request as Request & { mcpIdentity?: McpIdentity }).mcpIdentity;
  let subject: string;
  let scopes: ReadonlySet<string>;
  let tokenId: string | undefined;

  if (internalIdentity) {
    subject = internalIdentity.subject;
    scopes = internalIdentity.scopes;
    tokenId = internalIdentity.tokenId;
  } else {
    const auth = request.auth;
    subject = (auth?.extra?.subject as string | undefined) ?? "";
    if (!auth || typeof subject !== "string" || subject.length === 0) {
      response.status(401).json({ error: "invalid_token" });
      return;
    }
    scopes = new Set(auth.scopes);
    delete request.auth;
  }

  const server = createMcpServer({
    controlPlane,
    identity: { subject, scopes, ...(tokenId !== undefined ? { tokenId } : {}) }
  });
  const transport = new StreamableHTTPServerTransport({
    enableJsonResponse: true
  });
  let closed = false;
  const close = (): void => {
    if (closed) return;
    closed = true;
    void server.close();
  };
  response.once("finish", close);
  response.once("close", close);

  try {
    // SDK 1.30 has an exactOptionalPropertyTypes mismatch between this transport and Transport.
    await server.connect(transport as unknown as Transport);
    await transport.handleRequest(request, response, request.body);
  } catch {
    if (!response.headersSent) {
      response.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null
      });
    }
  }
}

function extractInternalToken(request: Request): string | null {
  const header = request.headers["x-session-token"];
  if (typeof header === "string" && header.length > 0) return header;
  const auth = request.headers.authorization;
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    const candidate = auth.slice(7).trim();
    if (isInternalToken(candidate)) return candidate;
  }
  return null;
}

function resolveInternalToken(controlPlane: ControlPlane, raw: string): TokenRecord | null {
  const cp = controlPlane as unknown as { resolveTokenFromRaw?: (r: string) => TokenRecord | null };
  if (typeof cp.resolveTokenFromRaw === "function") {
    return cp.resolveTokenFromRaw(raw);
  }
  return null;
}

function allowedOrigin(allowedOrigins: readonly string[]): RequestHandler {
  const allowed = new Set(allowedOrigins);
  return (request, response, next) => {
    const origin = request.get("origin");
    if (!origin) {
      next();
      return;
    }
    if (allowed.has(origin)) {
      response.set("Access-Control-Allow-Origin", origin).set("Vary", "Origin");
      next();
      return;
    }
    response.status(403).json({ error: "origin_not_allowed" });
  };
}

function methodNotAllowed(_request: Request, response: Response): void {
  response
    .status(405)
    .set("Allow", "POST")
    .json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
}

function requireJsonContentType(request: Request, response: Response, next: NextFunction): void {
  if (request.is("application/json")) {
    next();
    return;
  }
  response.status(415).json({ error: "unsupported_media_type" });
}

const safeErrorHandler: ErrorRequestHandler = (
  error: unknown,
  _request: Request,
  response: Response,
  next: NextFunction
) => {
  if (response.headersSent) {
    next(error);
    return;
  }
  const status = errorStatus(error);
  response.status(status).json({ error: status === 413 ? "request_too_large" : "invalid_request" });
};

function errorStatus(error: unknown): 400 | 413 {
  if (error !== null && typeof error === "object" && "status" in error && error.status === 413) return 413;
  return 400;
}
