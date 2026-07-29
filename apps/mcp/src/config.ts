import type { OidcVerifierConfig } from "./auth.js";

export interface HttpServerConfig {
  host: string;
  port: number;
  publicUrl: URL;
  allowedHosts: string[];
  allowedOrigins: string[];
  requestMaxBytes: number;
  rateLimitWindowMs: number;
  rateLimitMax: number;
  oidc: OidcVerifierConfig;
  authorizationUrl: URL;
  tokenUrl: URL;
}

export function loadHttpServerConfig(env: NodeJS.ProcessEnv = process.env): HttpServerConfig {
  if (env.SECUREIT_MODE !== "demo") {
    throw new Error("El servidor HTTP solo puede iniciar con el ejecutor sintético SECUREIT_MODE=demo");
  }

  const host = env.SECUREIT_HTTP_HOST ?? "127.0.0.1";
  const port = parseInteger(env.SECUREIT_HTTP_PORT ?? "3000", "SECUREIT_HTTP_PORT", 1, 65_535);
  const publicUrl = parseUrl(
    env.SECUREIT_MCP_PUBLIC_URL ?? `http://${host}:${String(port)}/mcp`,
    "SECUREIT_MCP_PUBLIC_URL",
    true
  );
  if (publicUrl.pathname !== "/mcp" || publicUrl.search || publicUrl.hash) {
    throw new Error("SECUREIT_MCP_PUBLIC_URL debe identificar exactamente el endpoint /mcp");
  }

  const issuer = parseUrl(required(env, "SECUREIT_OIDC_ISSUER"), "SECUREIT_OIDC_ISSUER", true);
  const jwksUri = parseUrl(required(env, "SECUREIT_OIDC_JWKS_URI"), "SECUREIT_OIDC_JWKS_URI", true);
  const authorizationUrl = parseUrl(
    required(env, "SECUREIT_OIDC_AUTHORIZATION_URL"),
    "SECUREIT_OIDC_AUTHORIZATION_URL",
    true
  );
  const tokenUrl = parseUrl(required(env, "SECUREIT_OIDC_TOKEN_URL"), "SECUREIT_OIDC_TOKEN_URL", true);
  const audience = required(env, "SECUREIT_OIDC_AUDIENCE");
  if (audience !== publicUrl.href) {
    throw new Error("SECUREIT_OIDC_AUDIENCE debe coincidir con SECUREIT_MCP_PUBLIC_URL");
  }
  if (issuer.search || issuer.hash) {
    throw new Error("SECUREIT_OIDC_ISSUER no admite query ni fragment");
  }
  const allowedHosts = parseAllowedHosts(env.SECUREIT_ALLOWED_HOSTS);
  if (allowedHosts.length === 0) {
    if (host === "0.0.0.0" || host === "::") {
      throw new Error("SECUREIT_ALLOWED_HOSTS es obligatorio al escuchar en todas las interfaces");
    }
    allowedHosts.push(host === "::1" ? "[::1]" : host);
  }

  return {
    host,
    port,
    publicUrl,
    allowedHosts,
    allowedOrigins: parseAllowedOrigins(env.SECUREIT_ALLOWED_ORIGINS),
    requestMaxBytes: parseInteger(
      env.SECUREIT_REQUEST_MAX_BYTES ?? "65536",
      "SECUREIT_REQUEST_MAX_BYTES",
      1_024,
      1_048_576
    ),
    rateLimitWindowMs: parseInteger(
      env.SECUREIT_RATE_LIMIT_WINDOW_MS ?? "60000",
      "SECUREIT_RATE_LIMIT_WINDOW_MS",
      1_000,
      3_600_000
    ),
    rateLimitMax: parseInteger(
      env.SECUREIT_RATE_LIMIT_MAX ?? "60",
      "SECUREIT_RATE_LIMIT_MAX",
      1,
      10_000
    ),
    oidc: {
      issuer: issuer.href,
      audience,
      jwksUri: jwksUri.href
    },
    authorizationUrl,
    tokenUrl
  };
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new Error(`${name} es obligatorio`);
  return value;
}

function parseUrl(value: string, name: string, allowDemoLoopbackHttp: boolean): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} no es una URL válida`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${name} no admite credenciales embebidas`);
  }
  const loopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]";
  if (parsed.protocol !== "https:" && !(allowDemoLoopbackHttp && parsed.protocol === "http:" && loopback)) {
    throw new Error(`${name} debe usar HTTPS; HTTP solo se admite en loopback para la demo`);
  }
  return parsed;
}

function parseInteger(value: string, name: string, minimum: number, maximum: number): number {
  if (!/^\d+$/u.test(value)) throw new Error(`${name} debe ser un entero`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} está fuera del rango permitido`);
  }
  return parsed;
}

function csv(value: string | undefined): string[] {
  return [...new Set((value ?? "").split(",").map((item) => item.trim()).filter(Boolean))];
}

function parseAllowedHosts(value: string | undefined): string[] {
  return csv(value).map((host) => {
    if (host === "::1") return "[::1]";
    let parsed: URL;
    try {
      parsed = new URL(`http://${host}`);
    } catch {
      throw new Error("SECUREIT_ALLOWED_HOSTS contiene un hostname no válido");
    }
    if (parsed.hostname !== host) {
      throw new Error("SECUREIT_ALLOWED_HOSTS solo admite hostnames sin puerto");
    }
    return parsed.hostname;
  });
}

function parseAllowedOrigins(value: string | undefined): string[] {
  return csv(value).map((origin) => {
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      throw new Error("SECUREIT_ALLOWED_ORIGINS contiene un origen no válido");
    }
    if (parsed.origin !== origin || (parsed.protocol !== "https:" && !isLoopback(parsed))) {
      throw new Error("SECUREIT_ALLOWED_ORIGINS exige orígenes HTTPS o loopback HTTP sin ruta");
    }
    return parsed.origin;
  });
}

function isLoopback(url: URL): boolean {
  return url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
}
