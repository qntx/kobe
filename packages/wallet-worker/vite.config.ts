import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const config: UserConfig = defineConfig({
  pack: {
    entry: {
      browser: "src/browser/index.ts",
      node: "src/node/index.ts",
    },
    dts: {
      generator: "tsgo",
      // The package tsconfig splits src by platform lib (browser/worker are nested
      // programs); declaration emit for both entries uses one merged program instead.
      tsconfig: "tsconfig.pack.json",
    },
    deps: {
      neverBundle: ["@qntx/wallet"],
    },
    sourcemap: true,
  },
  test: {
    // Playwright specs live in tests/browser and are not part of `vp test`.
    include: ["tests/*.test.ts"],
    coverage: { provider: "v8", reporter: ["text", "text-summary"], include: ["src/**/*.ts"] },
  },
});

export default config;
