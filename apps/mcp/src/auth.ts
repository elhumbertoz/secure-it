import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyGetKey,
  type JWTPayload
} from "jose";

const allowedAlgorithms = ["RS256", "PS256", "ES256"] as const;

export interface OidcVerifierConfig {
  issuer: string;
  audience: string;
  jwksUri: string;
  clockToleranceSeconds?: number;
}

export class OidcJwtVerifier implements OAuthTokenVerifier {
  private readonly getKey: JWTVerifyGetKey;

  constructor(
    private readonly config: OidcVerifierConfig,
    getKey?: JWTVerifyGetKey
  ) {
    this.getKey = getKey ?? createRemoteJWKSet(new URL(config.jwksUri));
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const { payload } = await jwtVerify(token, this.getKey, {
        algorithms: [...allowedAlgorithms],
        issuer: this.config.issuer,
        audience: this.config.audience,
        clockTolerance: this.config.clockToleranceSeconds ?? 5
      });
      return toAuthInfo(token, payload, this.config.audience);
    } catch {
      throw new InvalidTokenError("El token no es válido para este servidor MCP");
    }
  }
}

function toAuthInfo(token: string, payload: JWTPayload, audience: string): AuthInfo {
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new InvalidTokenError("El token no contiene un sujeto válido");
  }
  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
    throw new InvalidTokenError("El token no contiene expiración");
  }

  const clientId = stringClaim(payload.client_id) ?? stringClaim(payload.azp) ?? payload.sub;
  const authInfo: AuthInfo = {
    token,
    clientId,
    scopes: extractScopes(payload),
    expiresAt: payload.exp,
    extra: { subject: payload.sub }
  };
  if (URL.canParse(audience)) authInfo.resource = new URL(audience);
  return authInfo;
}

function extractScopes(payload: JWTPayload): string[] {
  const fromScope = typeof payload.scope === "string" ? payload.scope.split(/\s+/u) : [];
  const fromScp = Array.isArray(payload.scp)
    ? payload.scp.filter((scope): scope is string => typeof scope === "string")
    : [];
  return [...new Set([...fromScope, ...fromScp].filter((scope) => scope.length > 0))];
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
