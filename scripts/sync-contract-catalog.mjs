import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = new URL("..", import.meta.url);
const destination = new URL("packages/contracts/spec/", root);
mkdirSync(fileURLToPath(destination), { recursive: true });
copyFileSync(
  fileURLToPath(new URL("spec/mcp-tools.json", root)),
  fileURLToPath(new URL("mcp-tools.json", destination))
);
