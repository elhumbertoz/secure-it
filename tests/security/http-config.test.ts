import { describe, expect, it } from "vitest";
import { loadHttpServerConfig } from "../../apps/mcp/src/config.js";

const validEnvironment: NodeJS.ProcessEnv = {
  SECUREIT_MODE: "demo",
  SECUREIT_HTTP_HOST: "127.0.0.1",
  SECUREIT_HTTP_PORT: "3000",
  SECUREIT_MCP_PUBLIC_URL: "http://127.0.0.1:3000/mcp",
  SECUREIT_OIDC_ISSUER: "http://127.0.0.1:8080/realms/secure-it",
  SECUREIT_OIDC_AUDIENCE: "http://127.0.0.1:3000/mcp",
  SECUREIT_OIDC_JWKS_URI: "http://127.0.0.1:8080/realms/secure-it/protocol/openid-connect/certs",
  SECUREIT_OIDC_AUTHORIZATION_URL:
    "http://127.0.0.1:8080/realms/secure-it/protocol/openid-connect/auth",
  SECUREIT_OIDC_TOKEN_URL:
    "http://127.0.0.1:8080/realms/secure-it/protocol/openid-connect/token",
  SECUREIT_ALLOWED_HOSTS: "127.0.0.1",
  SECUREIT_ALLOWED_ORIGINS: "http://127.0.0.1:5173"
};

describe("configuración HTTP segura", () => {
  it("carga una configuración demo explícita", () => {
    const config = loadHttpServerConfig(validEnvironment);
    expect(config.allowedHosts).toEqual(["127.0.0.1"]);
    expect(config.allowedOrigins).toEqual(["http://127.0.0.1:5173"]);
    expect(config.oidc.audience).toBe("http://127.0.0.1:3000/mcp");
  });

  it("rechaza por defecto una configuración OIDC incompleta", () => {
    const environment = { ...validEnvironment };
    delete environment.SECUREIT_OIDC_ISSUER;
    expect(() => loadHttpServerConfig(environment)).toThrow(/SECUREIT_OIDC_ISSUER/);
  });

  it("rechaza HTTP fuera de loopback", () => {
    expect(() =>
      loadHttpServerConfig({
        ...validEnvironment,
        SECUREIT_MCP_PUBLIC_URL: "http://secure-it.example/mcp"
      })
    ).toThrow(/HTTPS/);
  });

  it("exige que la audiencia sea el URI canónico y prohíbe credenciales en URLs", () => {
    expect(() =>
      loadHttpServerConfig({
        ...validEnvironment,
        SECUREIT_OIDC_AUDIENCE: "https://other-mcp.example/mcp"
      })
    ).toThrow(/SECUREIT_OIDC_AUDIENCE/);
    expect(() =>
      loadHttpServerConfig({
        ...validEnvironment,
        SECUREIT_OIDC_JWKS_URI: "https://user:synthetic@identity.example/jwks"
      })
    ).toThrow(/credenciales embebidas/);
  });

  it("exige allowlist de Host al escuchar en todas las interfaces", () => {
    const environment = {
      ...validEnvironment,
      SECUREIT_HTTP_HOST: "0.0.0.0"
    };
    delete environment.SECUREIT_ALLOWED_HOSTS;
    expect(() => loadHttpServerConfig(environment)).toThrow(/SECUREIT_ALLOWED_HOSTS/);
  });

  it("rechaza Origins con ruta o sin HTTPS fuera de loopback", () => {
    expect(() =>
      loadHttpServerConfig({
        ...validEnvironment,
        SECUREIT_ALLOWED_ORIGINS: "https://client.example/path"
      })
    ).toThrow(/SECUREIT_ALLOWED_ORIGINS/);
    expect(() =>
      loadHttpServerConfig({
        ...validEnvironment,
        SECUREIT_ALLOWED_ORIGINS: "http://client.example"
      })
    ).toThrow(/SECUREIT_ALLOWED_ORIGINS/);
  });
});
