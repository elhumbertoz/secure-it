import { Client } from "ssh2";
import { buildCommand, type ActionExecutor, type CredentialRotator, type CredentialRotationOutcome, type ScriptExecutor, type CredentialResolver, type ExecutionOutcome, type ResolvedCredential } from "./executor.js";
import { DomainError } from "./errors.js";
import type { ActionDefinition, ServerRecord } from "./types.js";

export interface SshExecutorOptions {
  /** Timeout de ejecución del comando en segundos (default 30). */
  commandTimeoutSeconds?: number;
  /** Timeout de handshake/autenticación SSH en segundos (default 15). */
  readyTimeoutSeconds?: number;
}

export class SshExecutor implements ActionExecutor, ScriptExecutor, CredentialRotator {
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

  async rotatePassword(server: ServerRecord, newPassword: string): Promise<CredentialRotationOutcome> {
    const current = this.resolve(server);
    if (!current || current.kind !== "password" || !current.secret) {
      return { verified: false, error: "La credencial asociada no es una contraseña SSH" };
    }

    const changed = await this.changePasswordWithSudo(server, current, newPassword);
    if (changed.verified || changed.remoteMayHaveChanged) {
      const verified = await this.verifyPasswordLogin(server, current.username, newPassword);
      if (verified.verified) return verified;
    }
    return changed;
  }

  /**
   * Usa sudo/chpasswd con los secretos por stdin. Ningún secreto forma parte del
   * comando remoto, argv, stdout ni stderr. Requiere permiso sudo para chpasswd.
   */
  private changePasswordWithSudo(
    server: ServerRecord,
    current: ResolvedCredential,
    newPassword: string
  ): Promise<CredentialRotationOutcome> {
    return new Promise((resolve) => {
      const client = new Client();
      let settled = false;
      let credentialSubmitted = false;
      const finish = (result: CredentialRotationOutcome): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { client.end(); } catch { /* ignore */ }
        resolve(result);
      };
      const timer = setTimeout(
        () => finish({ verified: false, remoteMayHaveChanged: credentialSubmitted, error: "Timeout al cambiar la contraseña remota" }),
        this.commandTimeoutSeconds * 1000
      );

      client.on("ready", () => {
        // Algunos hosts aplican `Defaults use_pty` en sudo. Se desactiva el eco
        // antes de abrir el prompt para que ni la contraseña vigente ni la nueva
        // puedan reaparecer en la salida del pseudo-terminal.
        const command = "stty -echo; sudo -S -p '[secure-it-sudo]' sh -c 'echo [secure-it-ready]; exec chpasswd'";
        client.exec(command, { pty: true }, (err, stream) => {
          if (err) return finish({ verified: false, error: "No se pudo iniciar chpasswd" });
          let output = "";
          let sudoSent = false;
          let credentialSent = false;
          let exitCode: number | null = null;
          const consume = (chunk: Buffer): void => {
            output += chunk.toString("utf8");
            if (!sudoSent && output.includes("[secure-it-sudo]")) {
              sudoSent = true;
              stream.write(`${current.secret}\n`);
            }
            if (!credentialSent && output.includes("[secure-it-ready]")) {
              credentialSent = true;
              credentialSubmitted = true;
              stream.end(`${current.username}:${newPassword}\n`);
            }
          };
          stream.on("data", consume);
          stream.stderr.on("data", consume);
          stream.on("exit", (code: number | null) => { exitCode = code; });
          stream.on("close", () => {
            if (exitCode === 0 && credentialSent) finish({ verified: true });
            else finish({ verified: false, remoteMayHaveChanged: credentialSent, error: "El servidor rechazó el cambio de contraseña" });
          });
        });
      });
      client.on("error", () => finish({ verified: false, error: "Falló la conexión SSH con la credencial vigente" }));
      client.connect(this.connectionConfig(server, current.username, current.secret));
    });
  }

  private verifyPasswordLogin(
    server: ServerRecord,
    username: string,
    password: string
  ): Promise<CredentialRotationOutcome> {
    return new Promise((resolve) => {
      const client = new Client();
      let settled = false;
      const finish = (result: CredentialRotationOutcome): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { client.end(); } catch { /* ignore */ }
        resolve(result);
      };
      const timer = setTimeout(
        () => finish({ verified: false, error: "Timeout al verificar la contraseña nueva" }),
        this.readyTimeoutSeconds * 1000
      );
      client.on("ready", () => finish({ verified: true }));
      client.on("error", () => finish({ verified: false, error: "La contraseña cambió, pero el nuevo login SSH no pudo verificarse" }));
      client.connect(this.connectionConfig(server, username, password));
    });
  }

  private connectionConfig(server: ServerRecord, username: string, password: string): Parameters<Client["connect"]>[0] {
    const expected = server.expectedHostIdentity.startsWith("SHA256:")
      ? server.expectedHostIdentity.slice("SHA256:".length)
      : null;
    const expectedHex = expected ? Buffer.from(expected, "base64").toString("hex") : null;
    return {
      host: server.endpoint.address,
      port: server.endpoint.port,
      username,
      password,
      readyTimeout: this.readyTimeoutSeconds * 1000,
      ...(server.labels.ssh_host_key_algorithm === "ssh-ed25519"
        ? { algorithms: { serverHostKey: ["ssh-ed25519" as const] } }
        : {}),
      ...(expectedHex
        ? { hostHash: "sha256", hostVerifier: (hash: string) => hash.toLowerCase() === expectedHex }
        : {})
    };
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
      if (server.expectedHostIdentity.startsWith("SHA256:")) {
        const expected = Buffer.from(server.expectedHostIdentity.slice("SHA256:".length), "base64").toString("hex");
        connectConfig.hostHash = "sha256";
        connectConfig.hostVerifier = (hash: string) => hash.toLowerCase() === expected;
      }
      if (server.labels.ssh_host_key_algorithm) {
        connectConfig.algorithms = { serverHostKey: [server.labels.ssh_host_key_algorithm] };
      }
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
