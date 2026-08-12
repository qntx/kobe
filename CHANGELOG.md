# Changelog

All notable changes to this workspace are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [3.4.0] - 2026-08-12

### Added

- **Arweave ECDSA (`kobe-arweave`)** — offline HD derivation (SLIP-44 coin type
  `472`), secp256k1 only:
  - Path `m/44'/472'/0'/0/{i}`
  - Address: Base64URL(SHA-256(**compressed** 33-byte public key)) — matches
    protocol `ar_wallet` / arweave-js `master-ec` identifier hash
  - Helpers: `address_from_compressed_pubkey`, `owner_from_compressed_pubkey`
    (recovered owner encoding when tx `owner` is empty)
  - CLI: `kobe arweave` / `kobe ar` (`new` / `import`)
  - Umbrella feature: `arweave` (included in `all-chains`; not in `mainstream`)
  - Explicit non-goals: RSA-PSS wallets, transaction signing (future
    `signer-arweave`)
- Rewritten [`CONTRIBUTING.md`](CONTRIBUTING.md): full chain registration
  matrix (umbrella, CLI, CI no_std, crates.io publish order, docs, KATs).

### Fixed

- CI `no_std` job and crates.io publish order include `kobe-arweave`.

## [3.3.0] - 2026-08-09

### Added

- `Wallet::from_mnemonic_expanded` — 4-letter English BIP-39 prefix expansion
  (same path as CLI `import`); CLI `build_wallet` uses this single library API.

### Changed

- README library examples require explicit Cargo features (`mainstream` / chains).
- `crates/README` feature table: default is `std` only (removed incorrect `svm` default mark).

## [3.2.0] - 2026-08-08

### Added

- **Casper Network (`kobe-casper`)** — offline HD derivation for CSPR
  (SLIP-44 coin type `506`):
  - Default algorithm **secp256k1** at Ledger path `m/44'/506'/0'/0/{i}`
  - Alternate **Ed25519** (SLIP-10) at `m/44'/506'/0'/0'/{i}'` via `--algo ed25519`
  - Primary address: Casper **AccountHash** (`account-hash-` + 64 hex);
    preimage matches `casper-types` (`algorithm_name || 0x00 || raw_pubkey`)
  - Library `CasperAccount::tagged_public_key_hex` for `01…` / `02…` serialization form
    (untagged raw key remains on `DerivedAccount::public_key_hex` via `Deref`)
  - CLI: `kobe casper` / `kobe cspr` (`new` / `import`)
  - Umbrella feature: `casper` (included in `all-chains`)
  - Cross-chain smoke KATs for default secp and ed25519 abandon@0

## [3.1.1] - 2026-08-08

### Security

- CLI `kobe mnemonic encrypt/decrypt` respects global `-r` / `--reveal` (phrases
  hidden by default, same policy as HD wallet output).
- Mnemonic prefix-expansion errors no longer echo the rejected token (avoids
  leaking partial secret material via stderr / JSON errors).

### Added

- Import and camouflage accept `-m -` / `-c -` to read a phrase from stdin
  (reduces shell-history exposure versus argv secrets).

### Changed

- `just all` / `make all` now run the full workspace test suite.
- Cross-chain smoke tests assert golden abandon@0 addresses for BTC, EVM, SVM,
  Cosmos, Tron, Spark, FIL, TON, Sui, Aptos, and XRPL.

## [3.1.0] - 2026-08-08

### Added

- CLI `kobe upgrade` (`update` alias): self-upgrade via the official
  `sh.qntx.fun` installer. Supports `--check`, `--force`, and `--json`.
  Cargo-installed binaries are not overwritten (prints `cargo install` hint).

### Changed

- Replaced the `docs/` directory with a root [`CONTRIBUTING.md`](CONTRIBUTING.md)
  (API contract, development workflow, release process). Matches common Rust
  community layout.
- Workspace crate versions bumped to **3.1.0**; lockfile refresh (`cc` 1.4.2).

## [3.0.0] - 2026-08-08

### Security

- Redacted `Debug` for secret-bearing types (`Wallet`, `DerivedAccount`, `BtcAccount`, `SvmAccount`, `NostrAccount`). `Zeroizing` does not redact; hand-written `Debug` prints `[REDACTED]` for mnemonic, seed, private keys, WIF, keypair, and `nsec`.
- CLI defaults to hiding mnemonic and private keys. Pass global `-r` / `--reveal` to include them in human and JSON output.

### Breaking (`kobe-cli`)

- HD JSON/human output omits `mnemonic` and `private_key` unless `-r` / `--reveal` is set. Scripts that need secrets must pass the flag.

### Breaking (`kobe-btc`)

- `Deriver::new(wallet, network)` is now infallible and returns `Self` (no longer `Result`). Call sites that used `?` should drop it.
- `DerivationPath::inner()` and `AsRef<bip32::DerivationPath>` removed. Paths are fully owned by `kobe-btc` (`as_str()`, `segments()`, `PathSegment`). No third-party path type is public.
- `kobe-btc` no longer depends on the `bip32` crate directly (derivation still uses `Wallet::derive_secp256k1` from primitives).

### Breaking (`kobe-primitives` / `kobe`)

- `Wallet::seed()` is **gated on feature `raw-seed`** (off by default). Prefer
  `derive_secp256k1` / `derive_ed25519` or chain `Deriver`s. Enable
  `features = ["raw-seed"]` on `kobe` or `kobe-primitives` only when an
  advanced integration truly needs the raw 64-byte BIP-39 seed.

### Changed

- Umbrella feature `btc` enables `bip32` like other secp256k1 chains.
- `cargo-deny` configured and wired into CI / Justfile; the full `bitcoin` crate is banned.
- P2TR docs match implementation (x-coordinate of tweaked `Q`; BIP-341 tweak `mod n`).
- New `kobe-primitives` feature `encoding`: shared `hash160`, `double_sha256`, `base58check_*`.
  Used by `kobe-btc`, `kobe-cosmos`, and `kobe-xrpl` (Tron keeps `bs58` check — different API surface).
- CLI HD output builders unified (`HdWalletOutput::new` / `AccountOutput::from_parts`).
- `kobe-ton` split into `style` / `address` / `deriver` modules (no behavior change).
- Cross-chain smoke tests: `cargo test -p kobe --all-features --test cross_chain_smoke`.
- Documented chain API contract (now maintained in `CONTRIBUTING.md`).

## [2.0.0]

Major API redesign for long-term maintainability. Every chain crate is touched; the changes are sweeping but bring the workspace to a single consistent shape: one error type, one public-key enum, one derivation trait with associated types, one shared `DerivationStyle` contract, and minimal default features.

### Breaking: unified public-key type

- New [`DerivedPublicKey`](crates/kobe-primitives/src/derive.rs) enum replaces the opaque `Vec<u8>` field on `DerivedAccount`. Each variant fixes its algorithm and length at the type level: `Secp256k1Compressed([u8; 33])`, `Secp256k1Uncompressed([u8; 65])`, `Ed25519([u8; 32])`, `Secp256k1XOnly([u8; 32])`. Cross-chain code can now pattern match on the variant instead of guessing the layout from the byte length.
- New `PublicKeyKind` tag enum for cases where the bytes are not needed (`kind()` on `DerivedPublicKey`).
- `DerivedAccount::new` now takes `DerivedPublicKey` instead of `Vec<u8>`. `public_key_bytes()`/`public_key_hex()` remain available and delegate to the enum, so read-only call sites are unaffected.
- New `DerivedPublicKey::compressed` / `uncompressed` fallible constructors for call sites that start from a byte slice.

### Breaking: `Derive` trait with associated `Account` type

- `Derive::Account: AsRef<DerivedAccount>` — every chain now declares the concrete account type it returns, so chain-specific newtypes (`BtcAccount`, `SvmAccount`, `NostrAccount`) are returned *without* erasure.
- `DeriveExt::derive_many` returns `Vec<Self::Account>` instead of `Vec<DerivedAccount>`. Previously `btc_deriver.derive_many(...)` returned a `Vec<BtcAccount>` from the inherent method but a `Vec<DerivedAccount>` through the trait — the two silently disagreed. They now both return the newtype.
- Removed the BTC/SVM/Nostr inherent `derive_many` methods that duplicated the trait method. Call `DeriveExt::derive_many` (in scope via `use kobe::DeriveExt`). The `derive_many_with` inherent methods stay because they take a chain-specific `style` / `address_type` argument.
- `DerivedAccount` now implements `AsRef<Self>`; `BtcAccount`, `SvmAccount`, and `NostrAccount` implement `AsRef<DerivedAccount>` on top of their existing `Deref`.

### Breaking: one error type across the workspace

- Every chain crate now re-exports `kobe_primitives::DeriveError` instead of defining its own. Twelve `error.rs` files deleted; the `Core(#[from] ...)` wrapper variants are gone.
- New [`DeriveError::AddressEncoding(String)`](crates/kobe-primitives/src/error.rs) variant absorbs the former chain-local `Bech32(String)` (Nostr/Spark/TON), `AddressEncoding(String)` (Cosmos), and Filecoin/Sui base32/BLAKE2 failures. `Hashing` without context is replaced by `Crypto(String)` everywhere.
- BTC `InvalidPrivateKey`, `Bip32Error`, and `Secp256k1Error` map onto `DeriveError::Crypto(String)`.
- EVM `UnknownDerivationStyle(String)` maps onto `DeriveError::Input(String)`.
- SVM `Signature` is removed (never triggered in practice).

### Breaking: `derive_at_path` renamed to `derive_at`

Affects every chain with a custom-path entry point (EVM, Cosmos, Tron, Filecoin, XRPL, Sui, Aptos, TON, Spark, Nostr, SVM). The `Derive::derive_path` trait method is unchanged.

### Breaking: minimal default features on the `kobe` umbrella crate

- `default` is now `["std"]` only. The previous default set (`btc + evm + svm`) is available as the `mainstream` preset.
- `all-chains` preset unchanged.
- Binary size and compile time drop by ~50% for users that only need a subset of chains. Users on the old defaults should add `features = ["mainstream"]`.

### Breaking: shared `DerivationStyle` trait

The three per-chain `DerivationStyle` enums (`kobe-evm`, `kobe-svm`, `kobe-ton`) all shared the same shape — `path(u32) -> String`, `name() -> &'static str`, `Display`, `FromStr` — with three independent `ParseDerivationStyleError` types. Collapsed into a single contract in [`kobe-primitives::style`](crates/kobe-primitives/src/style.rs):

- New `kobe_primitives::DerivationStyle` trait with methods `path`, `name`, `all`.
- New `kobe_primitives::ParseDerivationStyleError` — chain + rejected input + full accepted-token list; `Display` output is a single actionable message with every alias listed.
- Chain `DerivationStyle` enums continue to exist as inherent types but now `impl kobe_primitives::DerivationStyle`. The inherent `path` / `name` methods on each enum are gone; bring the trait into scope (`use kobe::DerivationStyle as _;` or `use kobe::prelude::*;`) before calling them.
- `kobe-ton::DerivationStyle` gained `FromStr` (previously missing, for parity with EVM/SVM).
- `kobe-svm::DerivationStyle::id` is kept as an inherent `const fn` — it is Solana-specific and has no equivalent on other chains, so it does not belong on the trait.

### Breaking: `kobe-btc` entry points renamed for cross-chain consistency

`kobe-btc::Deriver` now exposes the same `derive_at` / `derive_at_with` pair as every other chain:

- `derive_bip32_path(&DerivationPath, AddressType)` → renamed to `derive_structured(&DerivationPath, AddressType)`.
- New `derive_at(&str)` — infers `AddressType` from the BIP-44 purpose segment (`44'` → P2PKH, `49'` → P2SH-P2WPKH, `84'` → P2WPKH, `86'` → P2TR). Mirrors every other chain's `derive_at`.
- New `derive_at_with(&str, AddressType)` — explicit-type escape hatch for non-standard paths (custom purposes, non-hardened first segments).

`Derive::derive_path` (trait method) now forwards to `derive_at`. Error messages that previously pointed users at `Deriver::derive_bip32_path` now point at `Deriver::derive_at_with`.

### Added

- `DerivedPublicKey`, `PublicKeyKind` re-exported from `kobe_primitives` and every chain crate.
- `camouflage::Version` enum and `encrypt_with`/`decrypt_with` entry points. The salt and iteration count are now attached to a versioned tag so future KDF changes can coexist with old ciphertexts. `Version::V1` is the default and matches 1.x behaviour bit-for-bit.
- `kobe::mainstream` feature (BTC + EVM + SVM) as a drop-in replacement for the 1.x default.
- `kobe::prelude` re-exports `DerivationStyle as _`, `ParseDerivationStyleError`, and every other common trait/type so `use kobe::prelude::*;` covers the full cross-chain surface in one import.
- New CLI flags on `kobe ton` (`--testnet`, `--bounceable`, `--workchain`, `--style`) and `kobe spark` (`--network`) so previously-library-only address configuration is reachable from the command line.

### Migration

```rust
// 1.x — opaque bytes, manual length inspection
let bytes: &[u8] = account.public_key_bytes();
match bytes.len() {
    33 => { /* compressed secp256k1 */ }
    65 => { /* uncompressed secp256k1 */ }
    32 => { /* ed25519 or x-only */ }
    _ => unreachable!(),
}

// 2.0 — typed enum, exhaustive match
use kobe::DerivedPublicKey;
match account.public_key() {
    DerivedPublicKey::Secp256k1Compressed(b) => { /* 33-byte compressed */ }
    DerivedPublicKey::Secp256k1Uncompressed(b) => { /* 65-byte uncompressed */ }
    DerivedPublicKey::Ed25519(b) => { /* 32-byte ed25519 */ }
    DerivedPublicKey::Secp256k1XOnly(b) => { /* 32-byte x-only */ }
    _ => { /* future-proof */ }
}
```

```rust
// 1.x — silently loses BtcAccount's WIF
let acct: DerivedAccount = deriver.derive(0)?;

// 2.0 — Derive::Account = BtcAccount, WIF preserved
let acct: BtcAccount = deriver.derive(0)?;
let wif = acct.private_key_wif();
```

```rust
// 1.x
match err {
    kobe_btc::DeriveError::Core(inner) => match inner { /* primitives */ },
    kobe_btc::DeriveError::Bip32(e) => /* ... */,
    kobe_btc::DeriveError::Secp256k1(e) => /* ... */,
    kobe_btc::DeriveError::InvalidPrivateKey => /* ... */,
}

// 2.0
use kobe::DeriveError;
match err {
    DeriveError::Mnemonic(e) => /* ... */,
    DeriveError::Path(s) => /* ... */,
    DeriveError::Crypto(s) => /* BIP-32, secp256k1, BLAKE2, … */,
    DeriveError::Input(s) => /* ... */,
    DeriveError::AddressEncoding(s) => /* Bech32, base58, base32, … */,
    _ => /* future-proof */,
}
```

```toml
# 1.x — opt out of the btc+evm+svm default set
kobe = { version = "1", default-features = false, features = ["std", "nostr"] }

# 2.0 — defaults are minimal; opt in to chains
kobe = { version = "2", features = ["nostr"] }           # just nostr + std
kobe = { version = "2", features = ["mainstream"] }      # previous 1.x default
kobe = { version = "2", features = ["all-chains"] }      # every chain
```

```rust
// 1.x — inherent derive_many on BTC / SVM / Nostr
let accounts: Vec<BtcAccount> = deriver.derive_many(0, 10)?;

// 2.0 — DeriveExt::derive_many returns Vec<Self::Account>
use kobe::DeriveExt;
let accounts: Vec<BtcAccount> = deriver.derive_many(0, 10)?;
```

```rust
// 1.x
let a = deriver.derive_at_path("m/44'/60'/0'/0/0")?;

// 2.0 — renamed for consistency
let a = deriver.derive_at("m/44'/60'/0'/0/0")?;
```

```rust
// 1.x — per-chain ParseDerivationStyleError + inherent `path` / `name`
use kobe_evm::{DerivationStyle, ParseDerivationStyleError};
let s = "ledger-live".parse::<DerivationStyle>()?;
let path = s.path(0);

// 2.0 — shared trait + shared error type
use kobe::prelude::*;                  // brings DerivationStyle trait into scope
use kobe::evm::DerivationStyle;
use kobe::ParseDerivationStyleError;   // re-exported by every chain crate
let s: DerivationStyle = "ledger-live".parse()?;
let path = s.path(0);                  // trait method
```

```rust
// 1.x — BTC's structural entry was named after BIP-32
let acct = deriver.derive_bip32_path(&parsed, AddressType::P2tr)?;

// 2.0 — structured entry (renamed; semantics unchanged)
let acct = deriver.derive_structured(&parsed, AddressType::P2tr)?;

// 2.0 — BTC now has the same string entry as every other chain
let acct = deriver.derive_at("m/86'/0'/0'/0/0")?;                       // infer type
let acct = deriver.derive_at_with("m/7'/0'/0'/0/0", AddressType::P2tr)?; // explicit
```

## [1.1.0]

Breaking across every crate. The most impactful changes are **address correctness fixes on Aptos and TON** and a complete rewrite of the **Spark** address encoder to match the official protocol.

### Security / correctness

- **Aptos**: fixed `authentication_key` byte order. The scheme byte is now appended *after* the public key (`SHA3-256(pubkey || 0x00)`) per the `aptos-stdlib` Move source of truth; previously it was prepended, which produced addresses that did **not** match any Aptos account. Downstream users **must re-derive** every Aptos address generated with prior releases.
- **TON**: fixed `walletId` computation on non-basechain workchains. The derivation now correctly folds the workchain byte into the v5r1 client context (`walletId = networkGlobalId ^ clientContext(workchain)`), so addresses generated with `workchain = -1` (masterchain) are now valid. Basechain (`workchain = 0`) addresses are unaffected.
- **Spark**: replaced the placeholder `spark:<pubkey_hex>` encoder with the official Bech32m address format. New path: `m/8797555'/<account>'/0'`. New address format: `spark1…` / `sparkt1…` / `sparks1…` / `sparkrt1…` / `sparkl1…`. Cross-verified against the independent `ethanmarcuss/spark-address` reference.

### Added

- `kobe-primitives::Wallet::derive_secp256k1` and `derive_ed25519` as the preferred entry points for chain derivers. All chain crates (including `kobe-btc`) derive through these shortcuts; raw seed access is no longer required for BIP-32/SLIP-10 pipelines.
- `kobe-primitives::DeriveExt::derive_range` — iterator-shaped batch derivation. Removes duplication of per-chain `derive_many` wrappers.
- `kobe-primitives::test_vectors` module (feature `test-vectors`) exposing `MNEMONIC_ABANDON` and `SEED_HEX_ABANDON` as `&'static str` constants (no `alloc` required).
- `kobe-nostr::NostrAccount` newtype with `nsec()` / `npub()` accessors and `Deref<Target = DerivedAccount>` for generic code.
- `kobe-ton::AddressFormat` (`DEFAULT`, `BOUNCEABLE`, `TESTNET`) decouples wire-format choice from key derivation.
- `kobe-cosmos::ChainConfig` + the `COSMOS_HUB`, `OSMOSIS`, `TERRA`, `JUNO`, `SECRET`, and `KAVA` presets.
- `kobe-spark::Network` enum (`Mainnet`, `Testnet`, `Signet`, `Regtest`, `Local`) and `SPARK_PURPOSE` constant.
- Per-crate `[package.metadata.docs.rs] all-features = true` so docs.rs renders every feature-gated API.
- New KAT regressions across the workspace, including the official Aptos, Spark, and TON v5r1 test vectors plus a `walletId` math test against the canonical values published in `@ton/core`.

### Changed

- `Wallet::seed()` now returns `&Zeroizing<[u8; 64]>` instead of `&[u8; 64]`, so raw seed bytes never appear on the stack without zeroize protection. Callers who previously held a `&[u8; 64]` should switch to the new `derive_secp256k1` / `derive_ed25519` shortcuts.
- All chain crates now surface their public error as `DeriveError::Core(#[from] kobe_primitives::DeriveError)` plus a small set of chain-local variants (e.g. `DeriveError::Bech32(String)` on Spark). The former `kobe-btc::DeriveError::InvalidDerivationPath`, `kobe-ton::DeriveError::Bip32Derivation`, and friends were folded into the shared enum.
- `kobe-cosmos::Deriver::with_config` now takes `ChainConfig` (builder pattern) instead of `(String, u32)`.
- `kobe-ton::Deriver::with_format` replaces the implicit mainnet / basechain / non-bounceable defaults with an explicit configuration surface.
- `kobe-spark::Deriver::new` now defaults to `Network::Mainnet`; `with_network(…)` selects an alternative network.
- Nine chain crates no longer declare an inherent `derive_many` method. Import `kobe_primitives::DeriveExt` to access it.

### Removed

- `kobe-nostr::account_nsec` free function. Use `NostrAccount::nsec()` on the account returned by `Deriver::derive` / `derive_many`.
- All `Deriver::derive_path` inherent methods that merely mirrored the `Derive::derive_path` trait method. The trait method remains.

### Migration

```rust
// Before
let addr = kobe_nostr::account_nsec(&account)?;

// After
use kobe_nostr::Deriver;
let account = Deriver::new(&wallet).derive(0)?;
let nsec = account.nsec();
let npub = account.npub();
```

```rust
// Before
let derived = kobe_spark::Deriver::new(&wallet).derive(0)?;
// address: "spark:<pubkey_hex>"  ← not a real Spark address

// After
use kobe_spark::{Deriver, Network};
let derived = Deriver::with_network(&wallet, Network::Mainnet).derive(0)?;
// address: "spark1…" bech32m
```

```rust
// Before
let fmt = ();  // no user-facing type
let wid = if testnet { 0x7FFF_FFFD } else { 0x7FFF_FF11 };  // bug on wc != 0

// After
let fmt = kobe_ton::AddressFormat::new(/* workchain */ -1, /* bounceable */ false, /* testnet */ false);
let wid = fmt.wallet_id();  // correct on any workchain
```

## [1.0.0]

First stable release. **Breaking across every crate**; see the migration notes below for a line-by-line diff of the public surface.

### Added

- `kobe-btc::BtcAccount` and `kobe-svm::SvmAccount` newtype wrappers that extend the unified `DerivedAccount` with chain-specific fields (`private_key_wif`, `address_type`, `bip32_path` for BTC; `keypair_base58` for SVM). Both implement `Deref<Target = DerivedAccount>` and `From<…> for DerivedAccount`.
- `kobe-nostr::account_nsec` free function for rendering a derived account as a NIP-19 `nsec1…` bech32 string when needed.
- `DerivedAccount::{path, private_key_bytes, private_key_hex, public_key_bytes, public_key_hex, address}` accessor methods.

### Changed

- `kobe_primitives::DerivedAccount` is now a struct with **private fields** and accessor methods (previously `pub` fields). The constructor takes `(String, Zeroizing<[u8; 32]>, Vec<u8>, String)` instead of four `String`s, so the private key lives as raw bytes and the public key as a chain-native byte vector. Hex views are generated on demand.
- `kobe_primitives::DeriveError` collapsed into four variants: `Mnemonic`, `Path`, `Crypto`, and `Input`. All former variants (`InvalidWordCount`, `EmptyPassword`, `KeyDerivation`, `PrefixTooShort`, `UnknownPrefix`, `AmbiguousPrefix`, `IndexOverflow`, `Slip10*`, `Bip32Derivation`, `InvalidHex`) map onto one of these four.
- `kobe-btc::Deriver` now returns `BtcAccount` from `derive` / `derive_with` / `derive_many`. The trait implementation (`Derive::derive`) still returns the unified `DerivedAccount`.
- `kobe-svm::Deriver` now returns `SvmAccount` from `derive` / `derive_with` / `derive_many`. The custom-path entry point was renamed from `derive_path` to `derive_at_path` to avoid clashing with `Derive::derive_path`.
- `Wallet::has_passphrase` now reflects whether the caller supplied `Some(_)` at construction time (previously it required the string to be non-empty).

### Removed

- `kobe_primitives::DerivedAccount::{private_key_bytes, public_key_bytes}` error-returning accessors — replaced by infallible borrows now that the fields are stored in their native types.
- `kobe-btc::DerivedAddress` and `kobe-svm::DerivedAddress` — superseded by `BtcAccount` / `SvmAccount`.
- The `hex` crate dependency from `kobe-btc`, `kobe-svm`, `kobe-nostr`, `kobe-ton`, and `kobe-xrpl` (no longer needed by production code).

### Migration

```rust
// 0.8 — struct literal style
let account = DerivedAccount {
    path: String::from("m/44'/60'/0'/0/0"),
    private_key: Zeroizing::new(hex::encode(bytes)),
    public_key: hex::encode(pubkey),
    address: addr,
};

// 1.0 — constructor with typed fields
let account = DerivedAccount::new(
    String::from("m/44'/60'/0'/0/0"),
    Zeroizing::new(bytes),   // raw 32-byte secret
    pubkey,                  // Vec<u8>
    addr,
);
let hex = account.private_key_hex();     // Zeroizing<String> on demand
let raw = account.private_key_bytes();   // &Zeroizing<[u8; 32]>
```

```rust
// BTC: match on the newtype, fall back to the trait for generic code
let btc = kobe_btc::Deriver::new(&wallet, Network::Mainnet)?
    .derive(0)?;                                 // BtcAccount
println!("wif = {}", btc.private_key_wif().as_str());
let unified: DerivedAccount = btc.into();        // for `Derive`-bound callers
```
