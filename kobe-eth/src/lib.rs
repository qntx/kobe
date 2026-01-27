//! Ethereum wallet utilities for Kobe CLI.
//!
//! Provides Ethereum address derivation from a unified [`kobe_core::Wallet`].
//!
//! # Features
//!
//! - `std` (default): Enable standard library support
//! - `alloc`: Enable heap allocation without full std (for `no_std` environments)
//! - `rand`: Enable random key generation for `StandardWallet`
//!
//! # Usage
//!
//! ```
//! use kobe_core::Wallet;
//! use kobe_eth::Deriver;
//!
//! // Create a wallet from kobe-core
//! let wallet = Wallet::generate(12, None).unwrap();
//!
//! // Derive Ethereum addresses from the wallet
//! let deriver = Deriver::new(&wallet);
//! let addr = deriver.derive(0, false, 0).unwrap();
//! println!("Address: {}", addr.address);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;
#[cfg(feature = "alloc")]
mod standard_wallet;
#[cfg(feature = "alloc")]
mod utils;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;
#[cfg(feature = "alloc")]
pub use standard_wallet::StandardWallet;
