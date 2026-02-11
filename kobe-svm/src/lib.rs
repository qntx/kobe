//! Solana wallet utilities for Kobe CLI.
//!
//! Provides Solana address derivation from a unified [`kobe::Wallet`].
//!
//! # Features
//!
//! - `std` (default): Enable standard library support
//! - `alloc`: Enable heap allocation without full std (for `no_std` environments)
//! - `rand`: Enable random key generation for `StandardWallet`

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod derivation_style;
#[cfg(feature = "alloc")]
mod deriver;
mod error;
#[cfg(feature = "alloc")]
mod slip10;
#[cfg(feature = "alloc")]
mod standard_wallet;

#[cfg(feature = "alloc")]
pub use derivation_style::{DerivationStyle, ParseDerivationStyleError};
#[cfg(feature = "alloc")]
pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;
#[cfg(feature = "alloc")]
pub use standard_wallet::StandardWallet;

/// A convenient Result type alias for kobe-svm operations.
pub type Result<T> = core::result::Result<T, Error>;
