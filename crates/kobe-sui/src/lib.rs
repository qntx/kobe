//! Sui wallet utilities for Kobe.
//!
//! Provides Sui address derivation from a unified [`kobe_primitives::Wallet`].
//! Uses SLIP-10 Ed25519 derivation at path `m/44'/784'/{index}'/0'/0'`.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::Deriver;
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
