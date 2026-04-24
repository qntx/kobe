//! Ethereum HD wallet derivation.
//!
//! Derives Ethereum (EIP-55 checksummed) addresses from a [`kobe_primitives::Wallet`]
//! seed following BIP-32/44. Supports `MetaMask`, Ledger Live, and Ledger Legacy
//! derivation styles.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::{DerivationStyle, Deriver};
#[cfg(feature = "alloc")]
pub use kobe_primitives::ParseDerivationStyleError;
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
