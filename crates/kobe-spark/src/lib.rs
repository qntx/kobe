//! Spark protocol (Bitcoin L2) wallet utilities for Kobe.
//!
//! Implements the [Spark](https://docs.spark.money) identity-key derivation
//! and Bech32m address encoding from a unified [`kobe_primitives::Wallet`]:
//!
//! - **Derivation path**: `m/8797555'/{account}'/0'` — hardened BIP-32
//!   secp256k1. The purpose `8797555` is the Spark-specific constant
//!   (`SHA-256("spark")` truncated).
//! - **Address**: `spark1…` (Mainnet), `sparkt1…` (Testnet), `sparks1…`
//!   (Signet), `sparkrt1…` (Regtest), `sparkl1…` (Local) — Bech32m-encoded
//!   compressed identity public key wrapped in a minimal protobuf header.
//!
//! # Example
//!
//! ```no_run
//! use kobe_primitives::Wallet;
//! use kobe_spark::{Deriver, Network};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = Wallet::from_mnemonic(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!     None,
//! )?;
//! let account = Deriver::with_network(&wallet, Network::Mainnet).derive(0)?;
//! assert!(account.address().starts_with("spark1"));
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::{Deriver, Network, SPARK_PURPOSE};
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
