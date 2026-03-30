//! Solana HD wallet derivation for Kobe.
//!
//! Derives Solana addresses from a [`kobe::Wallet`] seed using SLIP-10 Ed25519.
//! Supports Phantom/Backpack, Trust Wallet, and Ledger Live derivation styles.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod derivation_style;
#[cfg(feature = "alloc")]
mod deriver;
mod error;
#[cfg(feature = "alloc")]
pub(crate) mod slip10;

#[cfg(feature = "alloc")]
pub use derivation_style::{DerivationStyle, ParseDerivationStyleError};
#[cfg(feature = "alloc")]
pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;

/// Convenient Result alias.
pub type Result<T> = core::result::Result<T, Error>;
