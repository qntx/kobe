//! Tron wallet utilities for Kobe.
//!
//! Provides Tron address derivation from a unified [`kobe::Wallet`].
//! Tron uses secp256k1 keys with base58check-encoded addresses (0x41 prefix).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAccount, Deriver};
pub use error::Error;

/// A convenient Result type alias for kobe-tron operations.
pub type Result<T> = core::result::Result<T, Error>;
