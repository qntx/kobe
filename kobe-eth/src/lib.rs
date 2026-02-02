//! Ethereum wallet utilities for Kobe CLI.
//!
//! Provides Ethereum address derivation from a unified [`kobe::Wallet`].
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
//! use kobe::Wallet;
//! use kobe_eth::{Deriver, DerivationStyle};
//!
//! // Create a wallet from mnemonic
//! let wallet = Wallet::from_mnemonic(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!     None
//! ).unwrap();
//!
//! // Derive Ethereum addresses from the wallet
//! let deriver = Deriver::new(&wallet);
//! let addr = deriver.derive(0, false, 0).unwrap();
//! println!("Address: {}", addr.address);
//!
//! // Derive using Ledger Live style
//! let addr = deriver.derive_with_style(DerivationStyle::LedgerLive, 0).unwrap();
//! println!("Ledger Live Address: {}", addr.address);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod address;
#[cfg(feature = "alloc")]
mod derivation_style;
#[cfg(feature = "alloc")]
mod deriver;
mod error;
#[cfg(feature = "alloc")]
mod standard_wallet;

#[cfg(feature = "alloc")]
pub use derivation_style::{DerivationStyle, ParseDerivationStyleError};
#[cfg(feature = "alloc")]
pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;
#[cfg(feature = "alloc")]
pub use standard_wallet::StandardWallet;

/// A convenient Result type alias for kobe-eth operations.
pub type Result<T> = core::result::Result<T, Error>;
