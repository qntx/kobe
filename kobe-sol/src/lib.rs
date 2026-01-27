//! Solana wallet utilities for Kobe CLI.
//!
//! Provides Solana address derivation from a unified [`kobe_core::Wallet`].
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
//! use kobe_sol::Deriver;
//!
//! // Create a wallet from mnemonic
//! let wallet = Wallet::from_mnemonic(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!     None
//! ).unwrap();
//!
//! // Derive Solana addresses from the wallet
//! let deriver = Deriver::new(&wallet);
//! let addr = deriver.derive(0).unwrap();
//! println!("Address: {}", addr.address);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;
#[cfg(feature = "alloc")]
mod slip10;
#[cfg(feature = "alloc")]
mod standard_wallet;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;
#[cfg(feature = "alloc")]
pub use standard_wallet::StandardWallet;
