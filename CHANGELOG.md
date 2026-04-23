# Changelog

All notable changes to this workspace are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0]

First stable release. **Breaking across every crate**; see the migration
notes below for a line-by-line diff of the public surface.

### Added

- `kobe-btc::BtcAccount` and `kobe-svm::SvmAccount` newtype wrappers that
  extend the unified `DerivedAccount` with chain-specific fields
  (`private_key_wif`, `address_type`, `bip32_path` for BTC;
  `keypair_base58` for SVM). Both implement `Deref<Target = DerivedAccount>`
  and `From<…> for DerivedAccount`.
- `kobe-nostr::account_nsec` free function for rendering a derived account
  as a NIP-19 `nsec1…` bech32 string when needed.
- `DerivedAccount::{path, private_key_bytes, private_key_hex,
  public_key_bytes, public_key_hex, address}` accessor methods.

### Changed

- `kobe_primitives::DerivedAccount` is now a struct with **private fields** and
  accessor methods (previously `pub` fields). The constructor takes
  `(String, Zeroizing<[u8; 32]>, Vec<u8>, String)` instead of four `String`s,
  so the private key lives as raw bytes and the public key as a chain-native
  byte vector. Hex views are generated on demand.
- `kobe_primitives::DeriveError` collapsed into four variants:
  `Mnemonic`, `Path`, `Crypto`, and `Input`. All former variants
  (`InvalidWordCount`, `EmptyPassword`, `KeyDerivation`, `PrefixTooShort`,
  `UnknownPrefix`, `AmbiguousPrefix`, `IndexOverflow`, `Slip10*`,
  `Bip32Derivation`, `InvalidHex`) map onto one of these four.
- `kobe-btc::Deriver` now returns `BtcAccount` from `derive` / `derive_with`
  / `derive_many`. The trait implementation (`Derive::derive`) still returns
  the unified `DerivedAccount`.
- `kobe-svm::Deriver` now returns `SvmAccount` from `derive` / `derive_with`
  / `derive_many`. The custom-path entry point was renamed from
  `derive_path` to `derive_at_path` to avoid clashing with
  `Derive::derive_path`.
- `Wallet::has_passphrase` now reflects whether the caller supplied
  `Some(_)` at construction time (previously it required the string to be
  non-empty).

### Removed

- `kobe_primitives::DerivedAccount::{private_key_bytes, public_key_bytes}`
  error-returning accessors — replaced by infallible borrows now that the
  fields are stored in their native types.
- `kobe-btc::DerivedAddress` and `kobe-svm::DerivedAddress` — superseded by
  `BtcAccount` / `SvmAccount`.
- The `hex` crate dependency from `kobe-btc`, `kobe-svm`, `kobe-nostr`,
  `kobe-ton`, and `kobe-xrpl` (no longer needed by production code).

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
