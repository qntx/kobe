//! Filecoin wallet utilities for Kobe.
//!
//! Provides Filecoin f1 (secp256k1) address derivation from a unified [`kobe::Wallet`].

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAccount, Deriver};
pub use error::Error;

/// A convenient Result type alias for kobe-fil operations.
pub type Result<T> = core::result::Result<T, Error>;
