//! XRP Ledger wallet utilities for Kobe.
//!
//! Provides XRPL classic `r`-address derivation from a unified [`kobe::Wallet`]
//! using BIP-44 coin type 144 and secp256k1.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAccount, Deriver};
pub use error::DeriveError;

/// A convenient Result type alias for kobe-xrpl operations.
pub type Result<T> = core::result::Result<T, DeriveError>;
