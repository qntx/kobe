//! TON wallet utilities for Kobe.
//!
//! Provides TON wallet v5r1 address derivation from a unified [`kobe_primitives::Wallet`].
//! Uses SLIP-10 Ed25519 derivation at path `m/44'/607'/{index}'`.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::{AddressFormat, DerivationStyle, Deriver};
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
