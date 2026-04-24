//! Kobe core primitives — the foundation of every chain crate.
//!
//! This crate owns the type system shared by every `kobe-<chain>` crate:
//! the [`Wallet`] entry point, the [`Derive`] / [`DeriveExt`] traits, the
//! typed [`DerivedPublicKey`] enum, the unified [`DeriveError`], and the
//! BIP-32 / SLIP-10 / Camouflage primitives that chain crates compose.
//!
//! # Module map
//!
//! ```text
//!                        Wallet                (mnemonic + 64-byte BIP-39 seed)
//!                    ┌─────┴─────┐
//!    derive_secp256k1│           │  derive_ed25519
//!                    ▼           ▼
//!    bip32::DerivedSecp256k1Key     slip10::DerivedEd25519Key
//!                    │           │
//!    used by EVM / Cosmos /     │  used by Solana / Sui /
//!     Tron / Spark / Fil /       │  Aptos / TON
//!     XRPL / Nostr               │
//!                    └─────┬─────┘
//!                          ▼
//!                   DerivedAccount  ─◄── every chain wraps this
//!                   (path + sk + pk + address)
//! ```
//!
//! [`camouflage`] is an orthogonal utility (entropy-layer XOR encryption
//! that turns one BIP-39 mnemonic into another) gated behind its own feature.
//!
//! # Zeroize policy
//!
//! Every sensitive byte string is wiped when dropped:
//!
//! - [`Wallet`] — zeroizes the mnemonic and the 64-byte seed.
//! - [`DerivedAccount::private_key_bytes`] / [`private_key_hex`][`DerivedAccount::private_key_hex`]
//!   — hand out `&Zeroizing<…>` or `Zeroizing<…>` copies.
//! - [`bip32::DerivedSecp256k1Key`] / [`slip10::DerivedEd25519Key`] —
//!   zeroize their signing key material, chain code, and every byte view.
//! - [`camouflage::encrypt`] / [`camouflage::decrypt`] — return `Zeroizing<String>`.
//!
//! Public keys and on-chain addresses are **not** zeroized: by design they
//! carry no secret material.
//!
//! # `no_std` surface
//!
//! | Feature           | Needs `alloc` | Purpose                                |
//! | ----------------- | :-----------: | -------------------------------------- |
//! | `std`  (default)  |       ✔       | `std::error::Error`, OS RNG            |
//! | `alloc`           |       ✔       | [`Wallet`], [`DerivedAccount`], [`mnemonic`] |
//! | `bip32`           |       ✔       | [`bip32::DerivedSecp256k1Key`]         |
//! | `slip10`          |       ✔       | [`slip10::DerivedEd25519Key`]          |
//! | `camouflage`      |       ✔       | [`camouflage`] (PBKDF2 XOR helpers)    |
//! | `rand` / `rand_core` |     ✔       | [`Wallet::generate`]                   |
//! | `test-vectors`    |       ✗       | Re-export of canonical BIP-39 fixtures |
//!
//! Only [`DeriveError`] and [`test_vectors`] compile in pure `no_std`
//! without `alloc`. Everything else requires at least `alloc`.
//!
//! # Quick tour
//!
//! ```no_run
//! use kobe_primitives::Wallet;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Build a wallet from a BIP-39 mnemonic:
//! let wallet = Wallet::from_mnemonic(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!     None,
//! )?;
//!
//! // 2. Derive secp256k1 / Ed25519 keys at BIP-32 / SLIP-10 paths
//! //    (enable the `bip32` / `slip10` features):
//! # #[cfg(feature = "bip32")]
//! assert_eq!(wallet.derive_secp256k1("m/44'/60'/0'/0/0")?.compressed_pubkey().len(), 33);
//! # #[cfg(feature = "slip10")]
//! assert_eq!(wallet.derive_ed25519("m/44'/501'/0'/0'")?.public_key_bytes().len(), 32);
//! # Ok(())
//! # }
//! ```
//!
//! For chain-specific derivation (Bitcoin addresses, Ethereum checksummed
//! addresses, Solana keypairs, etc.), reach for the matching chain crate
//! (`kobe-btc`, `kobe-evm`, `kobe-svm`, …) via the [`kobe`] umbrella crate.
//!
//! [`kobe`]: https://docs.rs/kobe

#![cfg_attr(not(feature = "std"), no_std)]
// `proptest` is a workspace dev-dependency used only by the integration
// tests under `tests/`. Library-test compilation triggers rustc's
// `unused_crate_dependencies` lint; suppress it for test builds only so
// production compilation still enforces the lint.
#![cfg_attr(
    test,
    allow(
        unused_crate_dependencies,
        reason = "proptest is only referenced by the tests/ integration binary"
    )
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod derive;
mod error;
#[cfg(feature = "alloc")]
mod wallet;

#[cfg(feature = "bip32")]
pub mod bip32;
#[cfg(feature = "camouflage")]
pub mod camouflage;
#[cfg(feature = "alloc")]
pub mod mnemonic;
#[cfg(feature = "slip10")]
pub mod slip10;

pub use bip39::Language;
#[cfg(feature = "rand_core")]
pub use bip39::rand_core;
#[cfg(feature = "alloc")]
pub use derive::{
    Derive, DeriveExt, DerivedAccount, DerivedPublicKey, PublicKeyKind, derive_range,
};
pub use error::DeriveError;
#[cfg(feature = "alloc")]
pub use wallet::Wallet;

/// Convenient Result alias.
pub type Result<T> = core::result::Result<T, DeriveError>;

/// Well-known BIP-39 / SLIP-10 test vectors, exposed for downstream test suites.
///
/// Gated on the `test-vectors` feature so they do **not** ship with the
/// default binary/`lib` build. The module contains only `&'static str`
/// constants and is available in `no_std + no_alloc` environments.
#[cfg(feature = "test-vectors")]
pub mod test_vectors {
    /// All-zero 128-bit entropy — yields the canonical BIP-39 test mnemonic
    /// (`"abandon abandon … about"`). Cross-verified against the BIP-39
    /// reference implementations and `iancoleman.io/bip39`.
    pub const MNEMONIC_ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// 64-byte BIP-39 seed derived from [`MNEMONIC_ABANDON`] with an empty
    /// passphrase, lowercase hex.
    pub const SEED_HEX_ABANDON: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
}
