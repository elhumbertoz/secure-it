import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = new URL("..", import.meta.url).pathname;
const temp = mkdtempSync(join(tmpdir(), "secure-it-packages-"));
const packDir = join(temp, "packs");
mkdirSync(packDir);

const workspaces = [
  ["contracts", "@secure-it/contracts"],
  ["control-plane", "@secure-it/control-plane"],
  ["admin", "@secure-it/admin"],
  ["mcp", "@secure-it/mcp"]
];
const tarballs = {};
for (const [key, workspace] of workspaces) {
  const output = execFileSync(
    "npm",
    ["pack", "-w", workspace, "--pack-destination", packDir, "--json"],
    { cwd: root, encoding: "utf8" }
  );
  const [{ filename, files }] = JSON.parse(output);
  tarballs[key] = join(packDir, filename);
  if (!files.some((file) => file.path === "LICENSE") || !files.some((file) => file.path === "README.md")) {
    throw new Error(`${workspace} no incluye LICENSE y README.md`);
  }
  if (workspace === "@secure-it/admin" && !files.some((file) => file.path === "public/index.html")) {
    throw new Error("@secure-it/admin no incluye la interfaz web public/index.html");
  }
}

const consumer = join(temp, "consumer");
mkdirSync(consumer);
writeFileSync(join(consumer, "package.json"), JSON.stringify({
  private: true,
  type: "module",
  dependencies: Object.fromEntries(workspaces.map(([key, name]) => [name, `file:${tarballs[key]}`]))
}, null, 2));
execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund"], {
  cwd: consumer,
  stdio: "inherit"
});

await import(pathToFileURL(join(consumer, "node_modules/@secure-it/contracts/dist/index.js")));
await import(pathToFileURL(join(consumer, "node_modules/@secure-it/control-plane/dist/index.js")));
await import(pathToFileURL(join(consumer, "node_modules/@secure-it/admin/dist/server.js")));
for (const executable of [
  join(consumer, "node_modules/@secure-it/admin/dist/index.js"),
  join(consumer, "node_modules/@secure-it/mcp/dist/index.js")
]) {
  if (!existsSync(executable) || !readFileSync(executable, "utf8").startsWith("#!/usr/bin/env node")) {
    throw new Error(`Ejecutable inválido: ${executable}`);
  }
}
console.log("Paquetes verificados mediante una instalación aislada:", temp);
