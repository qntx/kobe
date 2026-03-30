//! Sui wallet utilities for Kobe.
//!
//! Provides Sui address derivation from a unified [`kobe::Wallet`].
//! Uses SLIP-10 Ed25519 derivation at path `m/44'/784'/{index}'/0'/0'`.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;
#[cfg(feature = "alloc")]
mod slip10;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;

/// A convenient Result type alias for kobe-sui operations.
pub type Result<T> = core::result::Result<T, Error>;
