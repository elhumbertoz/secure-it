import { Client } from "ssh2";
import { buildCommand, type ActionExecutor, type ScriptExecutor, type CredentialResolver, type ExecutionOutcome } from "./executor.js";
import { DomainError } from "./errors.js";
import type { ActionDefinition, ServerRecord } from "./types.js";

export interface SshExecutorOptions {
  /** Timeout de ejecución del comando en segundos (default 30). */
  commandTimeoutSeconds?: number;
  /** Timeout de handshake/autenticación SSH en segundos (default 15). */
  readyTimeoutSeconds?: number;
}

export class SshExecutor implements ActionExecutor, ScriptExecutor {
  readonly name = "ssh";
  private readonly resolve: CredentialResolver;
  private readonly commandTimeoutSeconds: number;
  private readonly readyTimeoutSeconds: number;

  constructor(resolver: CredentialResolver, options: SshExecutorOptions = {}) {
    this.resolve = resolver;
    this.commandTimeoutSeconds = options.commandTimeoutSeconds ?? 30;
    this.readyTimeoutSeconds = options.readyTimeoutSeconds ?? 15;
  }

  async execute(
    server: ServerRecord,
    action: ActionDefinition,
    params: Record<string, unknown>
  ): Promise<ExecutionOutcome> {
    const command = buildCommand(action, params);
    return this.runCommand(server, command, this.commandTimeoutSeconds);
  }

  async executeScript(
    server: ServerRecord,
    script: string,
    timeoutSeconds?: number
  ): Promise<ExecutionOutcome> {
    return this.runCommand(server, script, timeoutSeconds ?? this.commandTimeoutSeconds);
  }

  private runCommand(server: ServerRecord, command: string, timeoutSeconds: number): Promise<ExecutionOutcome> {
    const cred = this.resolve(server);
    if (!cred || !cred.secret) {
      throw new DomainError(
        "POLICY_DENIED",
        `No hay una credencial de login activa asociada a '${server.name}'. Importa o asocia una credencial por la consola administrativa.`
      );
    }

    const usePty = cred.kind === "password" && /\bsudo\b/.test(command);
    const sudoPromptRe = /\[sudo\] password for \S+:\s*$/;
    const ansiRe = /\x1b\[[0-9;]*[a-zA-Z]/g;

    return new Promise<ExecutionOutcome>((resolve) => {
      const started = Date.now();
      const client = new Client();
      let settled = false;
      const finish = (outcome: ExecutionOutcome): void => {
        if (settled) return;
        settled = true;
        try {
          client.end();
        } catch {
          /* ignore */
        }
        resolve(outcome);
      };

      const connectConfig: Record<string, unknown> = {
        host: server.endpoint.address,
        port: server.endpoint.port,
        username: cred.username,
        readyTimeout: this.readyTimeoutSeconds * 1000
      };
      if (cred.kind === "privateKey") {
        connectConfig.privateKey = cred.secret;
      } else {
        connectConfig.password = cred.secret;
      }

      const timer = setTimeout(() => {
        finish({ stdout: "", stderr: `secure-it: timeout tras ${timeoutSeconds}s`, exitCode: null, durationMs: Date.now() - started });
      }, timeoutSeconds * 1000);

      client.on("ready", () => {
        client.exec(command, { pty: usePty }, (err, stream) => {
          if (err) {
            clearTimeout(timer);
            finish({
              stdout: "",
              stderr: `secure-it: error de exec: ${err.message}`,
              exitCode: null,
              durationMs: Date.now() - started
            });
            return;
          }
          let stdout = "";
          let stderr = "";
          let exitCode: number | null = null;
          let passwordSent = false;

          stream.on("data", (chunk: Buffer) => {
            stdout += chunk.toString("utf8");
            if (usePty && !passwordSent && sudoPromptRe.test(stdout)) {
              stream.write(cred.secret + "\n");
              passwordSent = true;
              stdout = stdout.replace(sudoPromptRe, "");
            }
          });

          if (!usePty) {
            stream.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
          }

          stream.on("exit", (code: number | null) => {
            exitCode = code;
          });
          stream.on("close", () => {
            clearTimeout(timer);
            if (usePty) {
              stdout = stdout.replace(ansiRe, "").replace(/\r\n/g, "\n").replace(/\r/g, "");
            }
            finish({ stdout, stderr, exitCode, durationMs: Date.now() - started });
          });
        });
      });

      client.on("error", (err: Error & { code?: string }) => {
        clearTimeout(timer);
        const reason =
          err.code === "ECONNREFUSED"
            ? `conexión denegada por el host ${server.endpoint.address}:${server.endpoint.port}`
            : err.code === "ENOTFOUND"
              ? `host no resuelve: ${server.endpoint.address}`
              : err.code === "EHOSTUNREACH"
                ? `host inalcanzable`
                : err.message;
        finish({
          stdout: "",
          stderr: `secure-it: fallo SSH: ${reason}`,
          exitCode: null,
          durationMs: Date.now() - started
        });
      });

      try {
        client.connect(connectConfig as Parameters<typeof client.connect>[0]);
      } catch (err) {
        clearTimeout(timer);
        finish({ stdout: "", stderr: `secure-it: configuración SSH inválida: ${(err as Error).message}`, exitCode: null, durationMs: Date.now() - started });
      }
    });
  }
}