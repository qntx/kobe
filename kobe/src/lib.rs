//! Core wallet types for Kobe multi-chain wallet CLI.
//!
//! This crate provides the unified [`Wallet`] type that holds a BIP39 mnemonic
//! and derives seeds for multiple cryptocurrencies.
//!
//! # Features
//!
//! - `std` (default): Enable standard library support
//! - `alloc`: Enable heap allocation without full std (for `no_std` environments)

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
#[cfg(feature = "alloc")]
mod wallet;

pub use error::Error;
#[cfg(feature = "alloc")]
pub use wallet::Wallet;

pub use bip39::Language;

#[cfg(feature = "rand_core")]
pub use bip39::rand_core;

/// A convenient Result type alias for kobe-core operations.
pub type Result<T> = core::result::Result<T, Error>;
