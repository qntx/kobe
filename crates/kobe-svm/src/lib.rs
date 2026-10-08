//! Solana HD wallet derivation for Kobe.
//!
//! Derives Solana addresses from a [`kobe_core::Wallet`] seed using SLIP-10 Ed25519.
//! Supports Phantom/Backpack, Trust Wallet, and Ledger Live derivation styles.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod derivation_style;
mod deriver;

pub use derivation_style::DerivationStyle;
pub use deriver::{Deriver, SvmAccount};
pub use kobe_core::{DeriveError, DerivedAccount, DerivedPublicKey, ParseDerivationStyleError};
