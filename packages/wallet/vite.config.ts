import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const config: UserConfig = defineConfig({
  pack: {
    entry: {
      index: "src/index.ts",
      host: "src/host.ts",
      nostr: "src/nostr/index.ts",
      protocol: "src/protocol/index.ts",
      types: "src/types.ts",
    },
    deps: {
      neverBundle: ["@qntx/nostr"],
    },
    dts: {
      generator: "tsgo",
    },
    sourcemap: true,
  },
  test: {
    include: ["tests/**/*.{test,spec}.ts"],
  },
});

export default config;
