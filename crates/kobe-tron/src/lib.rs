//! Tron wallet utilities for Kobe.
//!
//! Provides Tron address derivation from a unified [`kobe_primitives::Wallet`].
//! Tron uses secp256k1 keys with base58check-encoded addresses (0x41 prefix).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::Deriver;
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
