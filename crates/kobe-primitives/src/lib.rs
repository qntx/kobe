//! Multi-chain HD wallet derivation library.
//!
//! Core [`Wallet`] type holds a BIP-39 mnemonic and derives seeds for
//! chain-specific derivers (`kobe-evm`, `kobe-btc`, `kobe-svm`, etc.).
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = kobe_primitives::Wallet::from_mnemonic(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!     None,
//! )?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

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
