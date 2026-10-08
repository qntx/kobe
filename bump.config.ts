import { defineConfig } from "bumpp";

// npm package and Cargo workspace versions are lockstep; bumpp rewrites every
// `x.y.z` occurrence of the current version in non-JSON files, so Cargo.toml
// picks up both [workspace.package].version and the `kobe-* = "=x.y.z"` deps.
const config: ReturnType<typeof defineConfig> = defineConfig({
  files: ["packages/kobe/package.json", "Cargo.toml"],
  // cargo update rewrites Cargo.lock for the new internal versions.
  execute: "cargo update --workspace",
  all: true,
  commit: true,
  tag: true,
  push: true,
});

export default config;
