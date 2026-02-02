//! Bitcoin wallet utilities for Kobe CLI.
//!
//! Provides Bitcoin address derivation from a unified [`kobe::Wallet`].
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
//! use kobe_btc::{Deriver, Network, AddressType};
//!
//! // Create a wallet from kobe-core
//! let wallet = Wallet::generate(12, None).unwrap();
//!
//! // Derive Bitcoin addresses from the wallet
//! let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
//! let addr = deriver.derive(AddressType::P2wpkh, 0, false, 0).unwrap();
//! println!("Address: {}", addr.address);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod address;
#[cfg(feature = "alloc")]
mod deriver;
mod error;
mod network;
#[cfg(feature = "alloc")]
mod standard_wallet;
mod types;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;
pub use network::{Network, ParseNetworkError};
#[cfg(feature = "alloc")]
pub use standard_wallet::StandardWallet;
#[cfg(feature = "alloc")]
pub use types::DerivationPath;
pub use types::{AddressType, ParseAddressTypeError};

/// A convenient Result type alias for kobe-btc operations.
pub type Result<T> = core::result::Result<T, Error>;
