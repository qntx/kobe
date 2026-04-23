//! Cosmos wallet utilities for Kobe.
//!
//! Provides Cosmos address derivation from a unified [`kobe_primitives::Wallet`].
//! Supports configurable bech32 human-readable parts (e.g. "cosmos", "osmo").

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;

#[cfg(feature = "alloc")]
pub use deriver::{ChainConfig, DerivedAccount, Deriver};
pub use error::DeriveError;

/// A convenient Result type alias for kobe-cosmos operations.
pub type Result<T> = core::result::Result<T, DeriveError>;
