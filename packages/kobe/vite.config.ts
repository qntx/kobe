import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

/** ESM-only sugar flattens to a string; keep types/import/default for pack entries. */
export function applyPackExports(pkgExports: Record<string, unknown>): Record<string, unknown> {
  for (const [key, value] of Object.entries(pkgExports)) {
    if (typeof value !== "string" || !value.endsWith(".mjs")) {
      continue;
    }
    pkgExports[key] = {
      types: value.replace(/\.mjs$/, ".d.mts"),
      import: value,
      default: value,
    };
  }
  return pkgExports;
}

const config: UserConfig = defineConfig({
  pack: {
    deps: { resolveDepSubpath: true },
    entry: {
      core: "src/core/index.ts",
      nostr: "src/nostr/index.ts",
      vault: "src/vault/index.ts",
      backend: "src/backend/index.ts",
    },
    dts: {
      generator: "tsgo",
    },
    sourcemap: true,
    exports: {
      customExports: applyPackExports,
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
  },
});

export default config;
