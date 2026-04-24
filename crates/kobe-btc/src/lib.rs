//! Bitcoin HD wallet derivation for Kobe.
//!
//! Derives Bitcoin addresses from a [`kobe_primitives::Wallet`] seed following
//! BIP-32/44/49/84/86. Supports P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR
//! address types across mainnet and testnet.
//!
//! # Architectural note: why `kobe-btc` does not use `kobe_primitives::bip32`
//!
//! Every other secp256k1 chain in the workspace derives keys through
//! [`kobe_primitives::Wallet::derive_secp256k1`] (backed by the `bip32`
//! crate). `kobe-btc` is the sole exception: it builds a
//! [`bitcoin::bip32::Xpriv`] directly from
//! [`kobe_primitives::Wallet::seed`] so the entire pipeline —
//! [`bitcoin::PrivateKey::to_wif`], [`bitcoin::key::CompressedPublicKey`],
//! the native [`bitcoin::Address`] enum, and the BIP-44/49/84/86 path
//! constants — stays inside the `bitcoin` crate's type system.
//!
//! The two BIP-32 implementations are held to the same test vectors (see
//! the `kat_bip84_*`, `kat_bip49_*`, `kat_bip86_*`, and `wif_roundtrips_*`
//! tests), so users never observe the divergence. If you need to unify on a
//! single secp256k1 pipeline, note that giving up Bitcoin's native
//! `Address` / WIF layer would require re-implementing every Bitcoin
//! address encoding by hand — a net negative for maintenance and audit.

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
