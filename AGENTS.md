# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- Rust crate layering: `kobe-core` is the leaf; every chain crate (`kobe-<chain>`) and `kobe-vault` depend only on `kobe-core`; the `kobe` umbrella re-exports `kobe-core` and every chain behind features; `kobe-cli` consumes only `kobe`. `scripts/check-layers.ts` enforces the graph and rejects unregistered `kobe-*` crates.
- Library crates (every crate except `kobe-cli`) are `no_std` + `alloc` and sans-IO. `std` (default) is an additive feature, and OS entropy stays behind the `os-rng` feature. They must build for `thumbv7m-none-eabi`, `wasm32-unknown-unknown`, and the iOS/Android targets with `--no-default-features`, with no `getrandom` in the dependency graph (CI `portable` job).
- `packages/*/src/` is platform-neutral: no Node-only or browser-only globals and no `node:*` imports (lint-enforced). All I/O is injected; there are no ambient singletons.
- Secret-bearing types zeroize on drop and redact `Debug`; never `#[derive(Debug)]` on them.

## Dependency policy

TypeScript runtime dependencies use caret ranges so consumers can deduplicate them against the rest of their dependency tree; devDependencies stay exact-pinned for reproducible builds. Rust dependencies are declared once in `[workspace.dependencies]`, and `deny.toml` bans the full `bitcoin` crate. Adopt releases at least 7 days old (Dependabot cooldown) and review upstream changelogs on every bump.

## Rust crates

- Follow the Rust API Guidelines. No `unsafe` (`unsafe_code = "deny"`), no panics, and no `unwrap`/`expect` in library code.
- Shared test vectors live in `vectors/` (see `vectors/README.md`) and every capability implemented in both languages is tracked in `parity.json`; both languages run the same files.
- npm and crates versions are lockstep: `bump.config.ts` bumps `packages/*/package.json` and `Cargo.toml` together, internal path dependencies pin `=<version>`, and `scripts/check-version.ts` guards drift.
- TOML is formatted by taplo (`.taplo.toml`, aligned `=`); run `taplo fmt`, and keep `taplo fmt --check` green in `bun run lint`.

## Commands

Local gate before a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo,
                                                    # version, layer and
                                                    # parity checks
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```
