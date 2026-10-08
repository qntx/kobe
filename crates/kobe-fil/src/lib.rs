//! Filecoin wallet utilities for Kobe.
//!
//! Provides Filecoin f1 (secp256k1) address derivation from a unified [`kobe_core::Wallet`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod deriver;

pub use deriver::Deriver;
pub use kobe_core::{DeriveError, DerivedAccount, DerivedPublicKey};
