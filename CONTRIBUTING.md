# Contributing to Kobe

Normative process for developing, extending, reviewing, and releasing Kobe.
Prefer this document over tribal knowledge. Incomplete chain wiring has been a
recurring defect; the [New chain registration matrix](#new-chain-registration-matrix)
lists every required touchpoint, including CI and crates.io publish order.

Agents: also read [`AGENTS.md`](AGENTS.md) for architecture rules. Process and
checklists live **here**.

---

## Principles

| Rule | Meaning |
| --- | --- |
| Small PRs | One problem per PR; reviewable diffs. |
| No invented APIs | Follow the [chain API contract](#chain-api-contract). |
| No compatibility debt | Remove obsolete paths; do not add dual APIs or migrations “for now.” |
| No banned stacks | Full `bitcoin` crate is denied (`deny.toml`). Encode addresses/WIF in-tree. |
| Secrets hygiene | Mnemonics, seeds, private keys, WIF, `nsec`, Solana keypairs: `Zeroizing` + redacted `Debug`. Never `#[derive(Debug)]` on secret-bearing types. |
| Independent KATs | Every derivation path is pinned to a third-party or protocol vector — not a dump of our own previous output. |

License: contributions are dual-licensed [MIT](LICENSE-MIT) OR
[Apache-2.0](LICENSE-APACHE) as stated in `README.md`.

---

## Prerequisites

| Tool | Role |
| --- | --- |
| Rust stable | Build, test, MSRV (`rust-version` in root `Cargo.toml`). |
| Rust nightly | `rustfmt` import grouping; Clippy workspace lints. |
| [`just`](https://github.com/casey/just) | Canonical task runner (`Justfile`). `Makefile` mirrors the same suite. |
| [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) | Licenses, bans, advisories, sources. |

```bash
rustup toolchain install stable nightly --component rustfmt,clippy
cargo install just cargo-deny
```

---

## Local quality gate

```bash
git clone https://github.com/qntx/kobe.git
cd kobe
just all
```

`just all` runs: **fmt → clippy-fix → check-no-std → deny → test**.

| Recipe | Purpose |
| --- | --- |
| `just all` | Default pre-PR gate |
| `just check-no-std` | Host-side no_std matrix (every library crate + umbrella `all-chains`) |
| `just test` | `cargo test --workspace --all-features` |
| `just deny` | `cargo deny check` |
| `just fmt` / `just clippy` | Format / lint |

CI (`.github/workflows/ci.yml`) also builds bare-metal `thumbv7m-none-eabi` per
library crate. Host `check-no-std` is necessary but not always sufficient: a
crate that pulls `std` accidentally may still pass host checks and fail CI.

When adding a chain, update **both** the local matrix (`Justfile` / `Makefile`)
and the CI `no-std` job — see the registration matrix below.

---

## Repository layout

```text
Cargo.toml                 workspace package versions, shared deps, lints
deny.toml                  licenses / bans / advisories / sources
Justfile / Makefile        local gates (keep in sync with each other)
.github/workflows/
  ci.yml                   lint, test, deny, no_std (thumbv7m-none-eabi)
  publish.yml              crates.io publish order
  release.yml              CLI binary release
crates/
  kobe-primitives/         Wallet, Derive, bip32, slip10, encoding, …
  kobe-<chain>/            one publishable crate per network
  kobe/                    umbrella re-exports + feature flags
  kobe-cli/                `kobe` binary (builds with all-chains)
  README.md                crate table, graph, feature table
skills/kobe/SKILL.md       agent-facing CLI contract
CONTRIBUTING.md            this file
CHANGELOG.md               Keep a Changelog
```

Library crates target `no_std` + `alloc`. Prefer
`Wallet::derive_secp256k1` / `derive_ed25519`. Feature `raw-seed` is an escape
hatch only.

---

## Chain API contract

### Construction

| Method | Contract |
| --- | --- |
| `Deriver::new(wallet) -> Self` | Infallible. Optional network/format via args or `with_*`. |
| `Deriver::new(wallet, network) -> Self` | BTC: network is a required second argument. |
| `with_config` / `with_network` / `with_algo` / … | Chain-specific; still infallible constructors. |

Do **not** return `Result` from `new` unless initialization can genuinely fail.

### Derivation

| Method | Contract |
| --- | --- |
| `derive(index)` | Default path / style. |
| `derive_at(path: &str)` | Arbitrary BIP-32 / SLIP-10 path (inherent). |
| `Derive::derive_path` | Trait method; **must** forward to `derive_at`. |
| `DeriveExt::derive_many(start, count)` | Batch of `derive(index)`. |
| `derive_with(style_or_type, index)` | Only when the chain has a style / type axis. |
| `derive_at_with(path, style_or_type)` | Non-standard path + explicit type (BTC). |
| `derive_structured` | Pre-parsed path object (BTC). |

### Account type

| Type | When |
| --- | --- |
| `DerivedAccount` | Default for most chains. |
| `BtcAccount` | WIF + address type + path. |
| `SvmAccount` | 64-byte keypair base58. |
| `NostrAccount` | `nsec` / `npub`. |
| `CasperAccount` | AccountHash + algo + tagged pubkey hex. |

Account newtypes implement `AsRef<DerivedAccount>` (and usually `Deref`).

### Key material

| API | Use |
| --- | --- |
| `Wallet::derive_secp256k1` / `derive_ed25519` | Preferred inside chain crates. |
| `Wallet::seed` | Feature `raw-seed` only (off by default). |

### Debug / secrets

| Type | `Debug` |
| --- | --- |
| `Wallet` | Redacts mnemonic and seed (`[REDACTED]`). |
| `DerivedAccount` | Redacts private key; path, pubkey, address visible. |
| Chain secret newtypes | Redact WIF / keypair / `nsec` / etc. |

### Errors

Surface `kobe_primitives::DeriveError` only (`Path`, `Crypto`, `Input`,
`AddressEncoding`, `Mnemonic`).

### Naming

| Correct | Forbidden |
| --- | --- |
| Inherent `derive_at` | `derive_at_path`, `derive_bip32_path` |
| Trait `derive_path` → forwards to `derive_at` | Dual public names for the same operation |

---

## New chain registration matrix

**Source of truth for “a chain exists”:** directory `crates/kobe-<name>/` with
package name `kobe-<name>`.

**Feature name** = package name without the `kobe-` prefix
(`kobe-arweave` → feature `arweave`, re-export `kobe::arweave`).

Complete **every** row before merge. Omitting CI or publish rows has shipped
broken releases before.

| # | Touchpoint | Required action |
| --- | --- | --- |
| 1 | `crates/kobe-<name>/` | Scaffold: `#![cfg_attr(not(feature = "std"), no_std)]`, features `std`/`alloc`, workspace lints, `Derive` + `derive_at`. |
| 2 | Root `Cargo.toml` | `[workspace.dependencies] kobe-<name> = { version = "<maj.min>", path = "…", default-features = false }`. Bump workspace `version` when releasing. |
| 3 | `crates/kobe/Cargo.toml` | Optional dep; feature `"name" = ["dep:kobe-<name>", "bip32" \| "slip10"]`; add to `std` / `alloc` lists (`kobe-<name>?/std`); add `"name"` to `all-chains`. Do **not** add to `mainstream` unless product decision says so. |
| 4 | `crates/kobe/src/lib.rs` | `#[cfg(feature = "name")] pub use kobe_<name> as name;` |
| 5 | `Justfile` `check-no-std` | `cargo check -p kobe-<name> --no-default-features --features alloc` |
| 6 | `Makefile` `check-no-std` | Same command as Justfile (keep mirrors identical). |
| 7 | `.github/workflows/ci.yml` job `no-std` | `cargo check -p kobe-<name> --target thumbv7m-none-eabi --no-default-features --features alloc` |
| 8 | `.github/workflows/publish.yml` | Insert `kobe-<name>` in `packages` **before** `kobe` and `kobe-cli` (after `kobe-primitives`). Alphabetical among chains is preferred. **If omitted, tag release will not publish the crate.** |
| 9 | `crates/kobe-cli` | Command module (`new` / `import` or chain-specific flags); clap primary `name = "<name>"` (aliases optional); `Commands` variant; `main.rs` match arm. Module **filename** may differ from feature name (`btc` → `bitcoin.rs`). Implementation must call `kobe::<name>::…`. |
| 10 | `crates/kobe/tests/cross_chain_smoke.rs` | abandon@0 (or chain-standard) assertion when `all-chains` is enabled. |
| 11 | KATs in chain crate | Independent reference vectors; document the source in the test comment. Negative test for the most likely wrong encoding (e.g. uncompressed vs compressed pubkey). |
| 12 | `README.md` | Supported-chains table row; intro / Design chain **count** and name list; Quick Start example if useful. |
| 13 | `crates/README.md` | Crate table, dependency graph, feature table, badge link anchors. |
| 14 | `skills/kobe/SKILL.md` | Chain table, aliases, path reference, private-key format, examples; keep chain count accurate. |
| 15 | `CHANGELOG.md` | User-visible entry under `[Unreleased]` or the release section. |
| 16 | Protocol accuracy | Cite protocol docs / reference clients in crate docs or KAT comments. |

### Worked example: Arweave ECDSA (`kobe-arweave`)

| Item | Value |
| --- | --- |
| Package / feature | `kobe-arweave` / `arweave` |
| Path | `m/44'/472'/0'/0/{i}` (SLIP-44 coin 472) |
| Address | `Base64URL_nopad(SHA-256(compressed 33-byte secp256k1 pubkey))` |
| References | [ECDSA Keys](https://docs.arweave.org/developers/development/overview/ecdsa-keys); node `ar_wallet.erl` (`ECDSA_PUB_KEY_SIZE = 33`); arweave-js `master-ec` |
| Out of scope | RSA-PSS wallets; transaction signing (companion signer crate) |
| CLI | `kobe arweave` / alias `ar` |

---

## Implementation guide for a new chain

1. **Protocol spike** — Address algorithm from primary sources (node code,
   official docs, reference client). Decide BIP-32 vs SLIP-10, coin type,
   pubkey encoding, hash, address alphabet. Record non-goals.
2. **Scaffold** — Copy the closest crate (`kobe-xrpl` for secp BIP-44;
   `kobe-sui` for SLIP-10 Ed25519).
3. **KAT first** — Lock gold vectors from an independent tool before API polish.
4. **Wire the matrix** — Rows 2–10, then 12–15. Manually verify CI and
   `publish.yml` (rows 7–8); they are the most commonly omitted.
5. **`just all`** — Fix Clippy, fmt, deny, tests.
6. **PR** — Title `feat(<name>): …`; body links protocol sources and KAT origin.

---

## CLI notes

| Topic | Rule |
| --- | --- |
| Global flags | `--json`, `-r` / `--reveal` (secrets hidden by default). |
| Mnemonics on shared hosts | Prefer `-m -` / stdin over argv. |
| Simple chains | Reuse `SimpleSubcommand` (`new` / `import`). |
| Complex chains | Dedicated modules (BTC network/type, EVM style, …). |
| Self-upgrade | `kobe upgrade` (`update` alias) via `sh.qntx.fun`; does not overwrite Cargo installs. |
| Agent contract | Keep `skills/kobe/SKILL.md` verbs and flags 1:1 with clap. |

---

## Commit and PR hygiene

- Imperative subjects: `feat(arweave): …`, `fix(btc): …`, `docs: …`, `ci: …`.
- Update `CHANGELOG.md` for user-visible behavior.
- Do not force-push shared branches without coordination.
- Crypto / new-chain PRs must state **protocol sources** and confirm the
  registration matrix (especially CI no_std + `publish.yml`).

### Reviewer checklist (crypto / new chain)

- [ ] Address algorithm matches cited protocol (not Ethereum-by-accident).
- [ ] Compressed vs uncompressed (or other encoding axes) explicit and tested.
- [ ] KATs cite independent source; negative test for the most likely wrong encoding.
- [ ] Matrix rows 5–8 complete: Justfile, Makefile, CI no_std, **publish.yml**.
- [ ] Secrets redacted; no `Debug` derive on secret types.
- [ ] `deny.toml` still clean (no full `bitcoin` crate).
- [ ] README / skill chain counts match the real set.

---

## Continuous integration

| Job | Workflow | Purpose |
| --- | --- | --- |
| `lint` | `ci.yml` | `cargo fmt --check`, Clippy `-D warnings`, all features. |
| `test` | `ci.yml` | Build + test workspace `--all-features`. |
| `deny` | `ci.yml` | `cargo-deny-action` with `--all-features`. |
| `no_std` | `ci.yml` | Per-crate `thumbv7m-none-eabi` + umbrella `all-chains`. |
| Publish | `publish.yml` on tag `v*.*.*` | Ordered crates.io publish. |
| Release | `release.yml` on tag | `kobe-cli` binaries. |

Publish package order in `publish.yml`:

```text
kobe-primitives → every kobe-<chain> → kobe → kobe-cli
```

A chain missing from this list will never reach crates.io on tag.

---

## Release process

Maintainers only.

1. `main` green on all CI jobs above.
2. Local: `just all`.
3. `CHANGELOG.md`: move `[Unreleased]` into a dated `## [X.Y.Z]` section.
4. Bump workspace `version` and path dependency version prefixes in root
   `Cargo.toml` (e.g. `3.4.0` with path deps `"3.4"`).
5. Tag and push:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

6. Confirm `release.yml` (binaries) and `publish.yml` (crates.io) succeed.

Semantic Versioning: breaking public API → major; new chain feature → minor;
fixes → patch. Document breaking changes in the changelog section.

---

## Security

This project has **not** been independently audited. Report vulnerabilities
privately to maintainers when possible. Never open public issues that include
live seed material or private keys.

---

## Getting help

| Resource | Path |
| --- | --- |
| Issues / PRs | [github.com/qntx/kobe](https://github.com/qntx/kobe) |
| Crate map | [`crates/README.md`](crates/README.md) |
| User overview | [`README.md`](README.md) |
| Agent architecture rules | [`AGENTS.md`](AGENTS.md) |
