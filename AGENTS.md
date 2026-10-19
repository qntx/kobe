# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- One `kobe` library crate — `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`,
  no `panic!`/`unwrap`/`expect`/indexing panics in production code — and one
  `kobe-cli` binary crate that consumes only `kobe`'s public API.
- kobe generates keys and addresses only: no signing, no vault, no storage,
  no network. OS entropy lives behind the `os-rng` feature; `getrandom` must
  never appear in a `--no-default-features` dependency graph.
- Secret material (entropy, mnemonic, seed, private keys) lives in
  `Zeroizing` buffers and is redacted from `Debug`; `String`/`Vec` copies of
  secret-derived bytes are never produced outside a `Zeroizing` guard.
- Each chain is a feature-gated module under `crates/kobe/src/chains/` with
  one `Chain` impl, reachable as `kobe::chains::<name>`; chain option enums
  use `option_enum!` and are the single source of truth for CLI choices.
  Canonical name = module = Cargo feature = CLI command (ticker aliases only).
- Every chain and every style is backed by official or independent reference
  vectors in `vectors/`, asserted byte-for-byte in `cargo test`.
- Dependencies are declared once in `[workspace.dependencies]`; `deny.toml`
  bans the `bitcoin` crate. Reference packages in `scripts/vectors` are
  exact-pinned and at least 7 days old at adoption time.

`design/` is local-only and never committed.

## Commands

Local gate before a pull request:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy -p kobe --all-targets --no-default-features -- -D warnings
cargo clippy -p kobe --all-targets --no-default-features --features all-chains -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
cargo build -p kobe --no-default-features --features all-chains --target thumbv7m-none-eabi
cargo build -p kobe --no-default-features --features all-chains --target wasm32-unknown-unknown
cargo tree -p kobe --no-default-features --features all-chains -e normal | grep getrandom   # must be empty
cargo deny check
cargo package --workspace --allow-dirty --no-verify
```

Each chain feature must also pass alone:

```bash
cargo clippy -p kobe --no-default-features --features <chain> --all-targets -- -D warnings
```

Regenerate reference vectors after touching a chain:

```bash
cd scripts/vectors && bun install && bun run generate
```

Second-source audit of the CLI against Trust Wallet Core:

```bash
cargo build -p kobe-cli && cd scripts/vectors && bun run crosscheck
```
