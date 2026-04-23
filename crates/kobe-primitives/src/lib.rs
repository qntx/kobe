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
pub use derive::{Derive, DeriveExt, DerivedAccount, derive_range};
pub use error::DeriveError;
#[cfg(feature = "alloc")]
pub use wallet::Wallet;

/// Convenient Result alias.
pub type Result<T> = core::result::Result<T, DeriveError>;
