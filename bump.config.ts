import { defineConfig } from "bumpp";

// All npm packages carry the lockstep release version — @qntx/wallet-kernel is private
// (never published) but still moves with them. Internal @qntx/* ranges (peer ^<v>, dev <v>)
// and the bun.lock refresh are run by sync-versions — bumpp spawns `execute` without a shell,
// so the string must stay a single command with no shell operators.
const config: ReturnType<typeof defineConfig> = defineConfig({
  files: [
    "packages/wallet/package.json",
    "packages/wallet-worker/package.json",
    "packages/wallet-kernel/package.json",
  ],
  execute: "bun scripts/sync-versions.ts",
  // execute rewrites bun.lock and the internal ranges; commit them too.
  all: true,
  commit: true,
  // main is protected: release through a `release/v<version>` pull request
  // opened via `gh`. No tag is created; after the release PR merges, tag the
  // merge commit by hand (GITHUB_TOKEN tags do not trigger publish workflows).
  pr: true,
  push: true,
});

export default config;
