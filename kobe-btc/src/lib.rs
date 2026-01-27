//! Bitcoin wallet utilities for Kobe CLI.
//!
//! Provides Bitcoin address derivation from a unified [`kobe_core::Wallet`].
//!
//! # Usage
//!
//! ```
//! use kobe_core::Wallet;
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

mod deriver;
mod error;
mod network;
mod types;
mod wallet;

pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;
pub use network::Network;
pub use types::{AddressType, DerivationPath};
pub use wallet::StandardWallet;
