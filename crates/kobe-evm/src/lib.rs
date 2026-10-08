//! Ethereum HD wallet derivation.
//!
//! Derives Ethereum (EIP-55 checksummed) addresses from a [`kobe_core::Wallet`]
//! seed following BIP-32/44. Supports `MetaMask`, Ledger Live, and Ledger Legacy
//! derivation styles.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod deriver;

pub use deriver::{DerivationStyle, Deriver};
pub use kobe_core::{DeriveError, DerivedAccount, DerivedPublicKey, ParseDerivationStyleError};
