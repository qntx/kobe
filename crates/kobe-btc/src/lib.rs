//! Bitcoin HD wallet derivation for Kobe.
//!
//! Derives Bitcoin addresses from a [`kobe_primitives::Wallet`] seed following
//! BIP-32/44/49/84/86. Supports P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR
//! address types across mainnet and testnet.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod address;
#[cfg(feature = "alloc")]
mod deriver;
mod network;
mod types;

#[cfg(feature = "alloc")]
pub use deriver::{BtcAccount, Deriver};
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
pub use network::{Network, ParseNetworkError};
#[cfg(feature = "alloc")]
pub use types::DerivationPath;
pub use types::{AddressType, ParseAddressTypeError};

/// Convenient Result alias.
pub type Result<T> = core::result::Result<T, DeriveError>;
