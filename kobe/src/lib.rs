//! # Kobe - Lightweight Multi-Chain Wallet Core Library
//!
//! A modern, `no_std` compatible wallet library providing core cryptographic
//! primitives and traits for building cryptocurrency wallets.
//!
//! ## Features
//!
//! - **no_std compatible**: Works in embedded and WASM environments
//! - **Modern cryptography**: Uses k256, sha3, and other audited libraries
//! - **Secure by design**: Zeroize secrets, constant-time operations
//! - **Minimal dependencies**: Lightweight and fast compilation

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod amount;
pub mod derivation_path;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod traits;
pub mod transaction;
pub mod types;
pub mod wordlist;

pub use amount::{BitcoinDenomination, EthereumDenomination, Satoshi, Wei};
pub use derivation_path::{ChildIndex, DerivationPath};
pub use error::{Error, Result};
pub use traits::*;
pub use transaction::{Eip1559TxParams, EthTxParams, SigHashType, TxInput, TxOutput};
pub use types::*;
pub use wordlist::bip39;

// Re-export rand_core from k256 for consistent RNG trait versions
pub use k256::elliptic_curve::rand_core;
