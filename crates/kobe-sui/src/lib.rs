//! Sui wallet utilities for Kobe.
//!
//! Provides Sui address derivation from a unified [`kobe_core::Wallet`].
//! Uses SLIP-10 Ed25519 derivation at path `m/44'/784'/{index}'/0'/0'`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod deriver;

pub use deriver::Deriver;
pub use kobe_core::{DerivedAccount, DerivedPublicKey, Error};
