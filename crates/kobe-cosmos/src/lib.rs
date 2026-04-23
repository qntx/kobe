//! Cosmos wallet utilities for Kobe.
//!
//! Provides Cosmos address derivation from a unified [`kobe_primitives::Wallet`].
//! Supports configurable bech32 human-readable parts (e.g. "cosmos", "osmo").

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::{ChainConfig, Deriver};
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
