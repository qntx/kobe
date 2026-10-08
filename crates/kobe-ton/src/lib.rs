//! TON wallet utilities for Kobe.
//!
//! Provides TON wallet v5r1 address derivation from a unified [`kobe_core::Wallet`].
//! Uses SLIP-10 Ed25519 derivation at path `m/44'/607'/{index}'`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod address;
mod deriver;
mod style;

pub use address::AddressFormat;
pub use deriver::Deriver;
pub use kobe_core::{DerivedAccount, DerivedPublicKey, Error, ParseDerivationStyleError};
pub use style::DerivationStyle;
