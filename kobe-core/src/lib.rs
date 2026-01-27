//! Core wallet types for Kobe multi-chain wallet CLI.
//!
//! This crate provides the unified [`Wallet`] type that holds a BIP39 mnemonic
//! and derives seeds for multiple cryptocurrencies.
//!
//! # Features
//!
//! - `std` (default): Enable standard library support
//! - `alloc`: Enable heap allocation without full std (for `no_std` environments)
//!
//! # Example
//!
//! ```
//! use kobe_core::Wallet;
//!
//! // Generate a new wallet (requires std or alloc feature with RNG)
//! let wallet = Wallet::generate(12, None).unwrap();
//!
//! // Or with a passphrase (BIP39 optional password)
//! let wallet = Wallet::generate(12, Some("my secret passphrase")).unwrap();
//!
//! // The same mnemonic can derive addresses for any coin
//! let seed = wallet.seed();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
#[cfg(feature = "alloc")]
mod wallet;

pub use error::Error;
#[cfg(feature = "alloc")]
pub use wallet::Wallet;
