//! Multi-chain HD wallet derivation library.
//!
//! Core [`Wallet`] type holds a BIP-39 mnemonic and derives seeds for
//! chain-specific derivers (`kobe-evm`, `kobe-btc`, `kobe-svm`, etc.).
//!
//! ```ignore
//! let wallet = kobe::Wallet::from_mnemonic("abandon ...", None)?;
//! let eth = kobe_evm::Deriver::new(&wallet).derive(0)?;
//! let btc = kobe_btc::Deriver::new(&wallet, kobe_btc::Network::Mainnet)?.derive(0)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod derive;
mod error;
#[cfg(feature = "alloc")]
mod wallet;

#[cfg(feature = "camouflage")]
pub mod camouflage;
#[cfg(feature = "alloc")]
pub mod mnemonic;

pub use bip39::Language;
#[cfg(feature = "rand_core")]
pub use bip39::rand_core;
#[cfg(feature = "alloc")]
pub use derive::{Derive, DerivedAccount};
pub use error::Error;
#[cfg(feature = "alloc")]
pub use wallet::Wallet;

/// Convenient Result alias.
pub type Result<T> = core::result::Result<T, Error>;
