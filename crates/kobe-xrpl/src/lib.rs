//! XRP Ledger wallet utilities for Kobe.
//!
//! Provides XRPL classic `r`-address derivation from a unified [`kobe_core::Wallet`]
//! using BIP-44 coin type 144 and secp256k1.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod deriver;

pub use deriver::Deriver;
pub use kobe_core::{DeriveError, DerivedAccount, DerivedPublicKey};
