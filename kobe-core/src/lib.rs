//! Core wallet types for Kobe multi-chain wallet CLI.
//!
//! This crate provides the unified [`Wallet`] type that holds a BIP39 mnemonic
//! and derives seeds for multiple cryptocurrencies.
//!
//! # Example
//!
//! ```
//! use kobe_core::Wallet;
//!
//! // Generate a new wallet
//! let wallet = Wallet::generate(12, None)?;
//!
//! // Or with a passphrase (BIP39 optional password)
//! let wallet = Wallet::generate(12, Some("my secret passphrase"))?;
//!
//! // The same mnemonic can derive addresses for any coin
//! let seed = wallet.seed();
//! # Ok::<(), kobe_core::Error>(())
//! ```

mod error;
mod wallet;

pub use error::Error;
pub use wallet::Wallet;
