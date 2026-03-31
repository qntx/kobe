//! Multi-chain HD wallet derivation — umbrella crate.
//!
//! This crate re-exports [`kobe_primitives`] and all chain-specific crates behind
//! feature flags, so a single dependency covers everything:
//!
//! ```toml
//! [dependencies]
//! kobe = { version = "0.7", features = ["evm", "btc", "svm"] }
//! ```
//!
//! ```ignore
//! use kobe::{Wallet, Derive, DeriveExt};
//! use kobe::evm::Deriver;
//!
//! let wallet = Wallet::from_mnemonic("abandon ...", None)?;
//! let addr = Deriver::new(&wallet).derive(0)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "btc")]
pub use kobe_btc as btc;
#[cfg(feature = "cosmos")]
pub use kobe_cosmos as cosmos;
#[cfg(feature = "evm")]
pub use kobe_evm as evm;
#[cfg(feature = "fil")]
pub use kobe_fil as fil;
pub use kobe_primitives::*;
#[cfg(feature = "spark")]
pub use kobe_spark as spark;
#[cfg(feature = "sui")]
pub use kobe_sui as sui;
#[cfg(feature = "svm")]
pub use kobe_svm as svm;
#[cfg(feature = "ton")]
pub use kobe_ton as ton;
#[cfg(feature = "tron")]
pub use kobe_tron as tron;
