//! XRP Ledger wallet utilities for Kobe.
//!
//! Provides XRPL classic `r`-address derivation from a unified [`kobe_primitives::Wallet`]
//! using BIP-44 coin type 144 and secp256k1.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::Deriver;
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
