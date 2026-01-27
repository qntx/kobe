//! Ethereum wallet utilities for Kobe CLI.
//!
//! Provides Ethereum address derivation from a unified [`kobe_core::Wallet`].
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

mod deriver;
mod error;
mod utils;
mod wallet;

pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;
pub use wallet::StandardWallet;
