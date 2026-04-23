# Changelog

All notable changes to this workspace are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0]

Breaking across every crate. The most impactful changes are **address correctness fixes on Aptos and TON** and a complete rewrite of the **Spark** address encoder to match the official protocol.

### Security / correctness

- **Aptos**: fixed `authentication_key` byte order. The scheme byte is now appended *after* the public key (`SHA3-256(pubkey || 0x00)`) per the `aptos-stdlib` Move source of truth; previously it was prepended, which produced addresses that did **not** match any Aptos account. Downstream users **must re-derive** every Aptos address generated with prior releases.
- **TON**: fixed `walletId` computation on non-basechain workchains. The derivation now correctly folds the workchain byte into the v5r1 client context (`walletId = networkGlobalId ^ clientContext(workchain)`), so addresses generated with `workchain = -1` (masterchain) are now valid. Basechain (`workchain = 0`) addresses are unaffected.
- **Spark**: replaced the placeholder `spark:<pubkey_hex>` encoder with the official Bech32m address format. New path: `m/8797555'/<account>'/0'`. New address format: `spark1…` / `sparkt1…` / `sparks1…` / `sparkrt1…` / `sparkl1…`. Cross-verified against the independent `ethanmarcuss/spark-address` reference.

### Added

- `kobe-primitives::Wallet::derive_secp256k1` and `derive_ed25519` as the preferred entry points for chain derivers. Raw seed bytes no longer leak out of the `Wallet` type for any chain other than Bitcoin (which still needs the raw seed for `bitcoin::bip32::Xpriv::new_master`).
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
