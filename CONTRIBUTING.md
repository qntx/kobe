# Contributing to Kobe

Thank you for improving Kobe. This document is the single source of truth for
how to develop, extend, and release the workspace. Please read it before
opening a pull request.

## Code of collaboration

- Prefer **small, reviewable PRs** with a clear problem statement.
- Match existing style: workspace Clippy lints (`pedantic` + `nursery`),
  `rustfmt` with the project config, explicit error handling.
- Do **not** invent APIs. Follow the [chain API contract](#chain-api-contract).
- Do **not** reintroduce the full `bitcoin` crate (`deny.toml` bans it).
- Secrets (mnemonics, private keys, WIF, `nsec`, Solana keypairs) must stay in
  `Zeroizing` and use **redacted `Debug`**. Never `#[derive(Debug)]` on types
  that hold secret material (`Zeroizing` itself does not redact).
- Every chain derivation path must be pinned with **cross-implementation KATs**
  (not self-confirming dumps).

By contributing, you agree that your contributions are dual-licensed under the
project’s [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) terms (see
`README.md`).

## Prerequisites

| Tool | Notes |
| --- | --- |
| Rust | Stable + nightly (fmt/clippy). MSRV is declared in root `Cargo.toml` (`rust-version`). |
| [`just`](https://github.com/casey/just) | Preferred task runner (`Justfile`; `Makefile` mirrors the same suite). |
| [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) | License / ban / advisory checks. |

```bash
rustup toolchain install stable nightly --component rustfmt,clippy
cargo install just cargo-deny
```

## Local development

```bash
git clone https://github.com/qntx/kobe.git
cd kobe

just all    # fmt + clippy-fix + no_std checks + cargo deny
just test   # cargo test --workspace --all-features
```

Useful recipes (see `just --list`):

| Recipe | Purpose |
| --- | --- |
| `just all` | Default quality gate before a PR |
| `just test` | Full workspace tests |
| `just check-no-std` | Host-side no_std feature matrix (CI also builds `thumbv7m-none-eabi`) |
| `just deny` | `cargo deny check` |
| `just fmt` / `just clippy` | Format and lint |

CI (`.github/workflows/ci.yml`) runs format, Clippy `-D warnings`, tests,
`cargo-deny`, and no_std targets. A PR should be green there.

### Commit and PR hygiene

- Use imperative commit subjects (`feat(cli): …`, `fix(btc): …`, `docs: …`).
- Reference issues when applicable.
- Update [`CHANGELOG.md`](CHANGELOG.md) under `[Unreleased]` for user-visible
  changes (Keep a Changelog format).
- Do not force-push shared branches without coordination.

## Project layout

```text
Cargo.toml              workspace + shared deps / lints
crates/
  kobe-primitives/      Wallet, Derive, bip32, slip10, encoding, …
  kobe-<chain>/         one crate per network
  kobe/                 umbrella re-exports + features
  kobe-cli/             `kobe` binary
crates/README.md        crate table, graph, features
deny.toml               licenses, bans (no full `bitcoin` crate)
```

Library crates target `no_std` + `alloc` where possible. Prefer
`Wallet::derive_secp256k1` / `derive_ed25519` over exposing the raw seed
(`raw-seed` feature is an escape hatch only).

## Chain API contract

Every `kobe-<chain>` deriver follows the same surface. Prefer this table when
adding a chain or reviewing API diffs.

### Construction

| Method | Contract |
| --- | --- |
| `Deriver::new(wallet) -> Self` | Infallible. Optional network/format via args or `with_*`. |
| `Deriver::new(wallet, network) -> Self` | BTC: network is a required second argument. |
| `with_config` / `with_network` / `with_format` | Chain-specific configuration; still infallible. |

Do **not** return `Result` from `new` unless initialization can fail for a
real reason.

### Derivation

| Method | Contract |
| --- | --- |
| `derive(index)` | Default path / style for the chain. |
| `derive_at(path: &str)` | Arbitrary BIP-32 / SLIP-10 path (inherent). |
| `Derive::derive_path` | Trait method; must forward to `derive_at`. |
| `DeriveExt::derive_many(start, count)` | Batch of `derive(index)`. |
| `derive_with(style_or_type, index)` | Only when the chain has a style / address-type axis. |
| `derive_at_with(path, style_or_type)` | Non-standard path + explicit type (BTC). |
| `derive_structured` | Pre-parsed path object (BTC). |

### Account type

| Type | When |
| --- | --- |
| `DerivedAccount` | Default for most chains. |
| `BtcAccount` | Extra WIF + address type + path. |
| `SvmAccount` | Extra keypair base58. |
| `NostrAccount` | Extra `nsec`. |

All account types implement `AsRef<DerivedAccount>` (and usually `Deref`).

### Key material

| Path | Use |
| --- | --- |
| `Wallet::derive_secp256k1` / `derive_ed25519` | Preferred inside chain crates. |
| `Wallet::seed` | **Feature `raw-seed` only** (off by default). |

### Debug / secrets

| Type | `Debug` contract |
| --- | --- |
| `Wallet` | Redacts mnemonic and seed (`[REDACTED]`). |
| `DerivedAccount` | Redacts private key; path, pubkey, address visible. |
| `BtcAccount` / `SvmAccount` / `NostrAccount` | Redacts WIF / keypair / `nsec`. |

### Errors

All chains surface `kobe_primitives::DeriveError` only (`Path`, `Crypto`,
`Input`, `AddressEncoding`, `Mnemonic`).

### Naming

- Inherent method: `derive_at`
- Trait method: `derive_path` (forwards to `derive_at`)
- Do not reintroduce `derive_at_path` / `derive_bip32_path`

## Adding a chain

1. Scaffold `crates/kobe-<name>/` with `no_std` + `alloc`, workspace lints, and
   `Derive` / `DeriveExt`.
2. Wire features on the `kobe` umbrella and `kobe-cli` (subcommand + output).
3. Add KATs against an independent reference implementation.
4. Extend `crates/kobe/tests/cross_chain_smoke.rs` when appropriate.
5. Document the path and address format in `README.md` and update
   `CHANGELOG.md`.
6. Keep `cargo deny` clean (no banned crates).

## CLI notes

- Global flags: `--json`, `-r` / `--reveal` (secrets hidden by default).
- Self-upgrade for installs from `https://sh.qntx.fun/kobe`:

  ```bash
  kobe upgrade              # alias: kobe update
  kobe upgrade --check
  ```

  Re-invokes the official installer. Cargo installs under `.cargo/bin` are
  **not** overwritten; the command prints a `cargo install kobe-cli --force`
  hint instead.

## Release process

Maintainers only.

1. CI green on `main` (`lint`, `test`, `deny`, `no_std`).
2. Local: `just all` and `just test`.
3. Move `[Unreleased]` notes in `CHANGELOG.md` into a dated version section;
   no leftover **Breaking** bullets that belong in the release.
4. Bump workspace `version` and path dependency major/minor strings in root
   `Cargo.toml` (e.g. `3.1.0` → path `"3.1"`).
5. Tag and push: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
6. Confirm GitHub Actions `release.yml` (binaries) and `publish.yml`
   (crates.io) succeed.
7. Publish order is handled by the workflow: `kobe-primitives` → chain crates →
   `kobe` → `kobe-cli`.

Semantic Versioning applies. Document breaking API changes under a major bump.

## Security

This project has **not** been independently audited. Report vulnerabilities
privately to the maintainers when possible; do not open public issues that
include live seed material or private keys.

## Getting help

- Issues and PRs: [github.com/qntx/kobe](https://github.com/qntx/kobe)
- Crate map: [`crates/README.md`](crates/README.md)
- User-facing overview: [`README.md`](README.md)
