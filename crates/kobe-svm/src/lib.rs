//! Solana HD wallet derivation for Kobe.
//!
//! Derives Solana addresses from a [`kobe_core::Wallet`] seed using SLIP-10 Ed25519.
//! Supports the BIP-44-change (`m/44'/501'/i'/0'`, e.g. Phantom / Solflare /
//! Backpack / `MetaMask` / OKX / solana-keygen), BIP-44 (`m/44'/501'/i'`,
//! e.g. Trust Wallet / Ledger Live / Keystone) and legacy Sollet
//! (`m/501'/i'/0'/0'`, deprecated) path layouts.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod derivation_style;
mod deriver;

pub use derivation_style::DerivationStyle;
pub use deriver::{Deriver, SvmAccount};
pub use kobe_core::{DerivedAccount, DerivedPublicKey, Error, ParseDerivationStyleError};
