import { defineConfig } from "bumpp";

// Cargo workspace release (tags v*.*.*). bumpp rewrites every `x.y.z`
// occurrence of the current version in non-JSON files, so Cargo.toml picks up
// both [workspace.package].version and the `kobe-* = "=x.y.z"` deps.
// The npm package is versioned independently — see bump.wallet.config.ts and
// `bun run release:wallet` (tags wallet-v*.*.*).
const config: ReturnType<typeof defineConfig> = defineConfig({
  files: ["Cargo.toml"],
  // cargo update rewrites Cargo.lock for the new internal versions.
  execute: "cargo update --workspace",
  all: true,
  commit: true,
  tag: true,
  push: true,
});

export default config;
