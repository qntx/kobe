//! Spark (Bitcoin L2) wallet utilities for Kobe.
//!
//! Provides Spark address derivation from a unified [`kobe_primitives::Wallet`].
//! Spark reuses Bitcoin's BIP-84 derivation path since it operates on the same keys.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAccount, Deriver};
pub use error::DeriveError;

/// A convenient Result type alias for kobe-spark operations.
pub type Result<T> = core::result::Result<T, DeriveError>;
