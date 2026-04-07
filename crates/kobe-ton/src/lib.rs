//! TON wallet utilities for Kobe.
//!
//! Provides TON wallet v5r1 address derivation from a unified [`kobe::Wallet`].
//! Uses SLIP-10 Ed25519 derivation at path `m/44'/607'/{index}'`.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;

#[cfg(feature = "alloc")]
pub use deriver::{DerivationStyle, DerivedAccount, Deriver};
pub use error::DeriveError;

/// A convenient Result type alias for kobe-ton operations.
pub type Result<T> = core::result::Result<T, DeriveError>;
