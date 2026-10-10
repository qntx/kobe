import { defineConfig } from "bumpp";

// Independent @qntx/wallet release (tags wallet-v*.*.*). The `%s` placeholder
// is replaced with the new version number. The Cargo workspace is versioned
// separately — see bump.config.ts.
const config: ReturnType<typeof defineConfig> = defineConfig({
  files: ["packages/wallet/package.json"],
  all: true,
  commit: true,
  tag: "wallet-v%s",
  push: true,
});

export default config;
