//! Multi-chain HD wallet derivation — umbrella crate.
//!
//! This crate re-exports [`kobe_primitives`] and all chain-specific crates behind
//! feature flags, so a single dependency covers everything:
//!
//! ```toml
//! [dependencies]
//! kobe = { version = "2.0", features = ["evm", "btc", "svm"] }
//! ```
//!
//! ```no_run
//! use kobe::prelude::*;
//! use kobe::evm::Deriver;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = Wallet::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None)?;
//! let account = Deriver::new(&wallet).derive(0)?;
//! println!("path={} address={}", account.path(), account.address());
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "aptos")]
pub use kobe_aptos as aptos;
#[cfg(feature = "btc")]
pub use kobe_btc as btc;
#[cfg(feature = "cosmos")]
pub use kobe_cosmos as cosmos;
#[cfg(feature = "evm")]
pub use kobe_evm as evm;
#[cfg(feature = "fil")]
pub use kobe_fil as fil;
#[cfg(feature = "nostr")]
pub use kobe_nostr as nostr;
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
#[cfg(feature = "xrpl")]
pub use kobe_xrpl as xrpl;

/// Common imports for downstream users.
///
/// Bring the core wallet traits and types into scope with a single
/// `use kobe::prelude::*;`. Chain-specific derivers (`kobe::evm::Deriver`,
/// `kobe::btc::Deriver`, …) remain explicit to avoid naming conflicts when
/// multiple chains are enabled simultaneously.
///
/// The [`DerivationStyle`](kobe_primitives::DerivationStyle) trait is
/// re-exported anonymously so calling `style.path(i)` / `style.name()` on
/// any chain's style enum works without manually `use`-ing the trait.
#[cfg(feature = "alloc")]
pub mod prelude {
    pub use kobe_primitives::DerivationStyle as _;
    pub use kobe_primitives::{
        Derive, DeriveError, DeriveExt, DerivedAccount, DerivedPublicKey,
        ParseDerivationStyleError, PublicKeyKind, Wallet,
    };
}
