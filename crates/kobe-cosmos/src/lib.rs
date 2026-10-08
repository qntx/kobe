//! Cosmos wallet utilities for Kobe.
//!
//! Provides Cosmos address derivation from a unified [`kobe_core::Wallet`].
//! Supports configurable bech32 human-readable parts (e.g. "cosmos", "osmo").

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod deriver;

pub use deriver::{ChainConfig, Deriver};
pub use kobe_core::{DeriveError, DerivedAccount, DerivedPublicKey};
