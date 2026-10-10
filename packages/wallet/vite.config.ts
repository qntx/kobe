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
      btc: "src/chains/btc/index.ts",
      evm: "src/chains/evm/index.ts",
      "evm/rlp": "src/chains/evm/rlp.ts",
      hd: "src/hd/index.ts",
      "hd/camouflage": "src/hd/camouflage.ts",
      "hd/raw-seed": "src/hd/raw-seed.ts",
      "hd/wordlists": "src/hd/wordlists.ts",
      nostr: "src/chains/nostr/index.ts",
      sign: "src/sign/index.ts",
      svm: "src/chains/svm/index.ts",
      vault: "src/vault/index.ts",
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
