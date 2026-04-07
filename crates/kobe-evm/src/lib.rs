//! Ethereum HD wallet derivation.
//!
//! Derives Ethereum (EIP-55 checksummed) addresses from a [`kobe::Wallet`]
//! seed following BIP-32/44. Supports `MetaMask`, Ledger Live, and Ledger Legacy
//! derivation styles.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;

#[cfg(feature = "alloc")]
pub use deriver::{DerivationStyle, DerivedAccount, Deriver};
pub use error::Error;

/// Convenient Result alias.
pub type Result<T> = core::result::Result<T, Error>;
