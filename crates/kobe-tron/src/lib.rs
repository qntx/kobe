//! Tron wallet utilities for Kobe.
//!
//! Provides Tron address derivation from a unified [`kobe_core::Wallet`].
//! Tron uses secp256k1 keys with base58check-encoded addresses (0x41 prefix).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod deriver;

pub use deriver::Deriver;
pub use kobe_core::{DerivedAccount, DerivedPublicKey, Error};
