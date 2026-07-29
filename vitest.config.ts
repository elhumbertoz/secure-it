import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@secure-it/contracts": fileURLToPath(new URL("./packages/contracts/src/index.ts", import.meta.url)),
      "@secure-it/control-plane": fileURLToPath(new URL("./packages/control-plane/src/index.ts", import.meta.url))
    }
  },
  test: {
    include: ["tests/**/*.test.ts"],
    coverage: {
      reporter: ["text", "json-summary"]
    }
  }
});
