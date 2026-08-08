//! Bitcoin HD wallet derivation for Kobe.
//!
//! Derives Bitcoin addresses from a [`kobe_primitives::Wallet`] seed following
//! BIP-32/44/49/84/86. Supports P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR
//! across mainnet and testnet.
//!
//! # Architecture
//!
//! - Key derivation: [`kobe_primitives::Wallet::derive_secp256k1`] (shared pipeline).
//! - Address and WIF: implemented in this crate and pinned by KATs
//!   (BIP-44/49/84/86; BIP-49 testnet official vectors; bitcoinjs-lib where noted).
//! - The workspace prefers thin wrappers around mature libraries; `kobe-btc`
//!   intentionally drops the `bitcoin` crate dependency while keeping the same
//!   derived address strings and WIF encoding.
//!
//! # Taproot scope
//!
//! Supported: single-key, key-path-only P2TR (BIP-86 style).
//! Not supported: script trees, merkle roots, `MuSig`, signing, or spending.
//! Internal keys use BIP-340 `lift_x` (even-y). The witness program is the
//! x-coordinate of the tweaked output key `Q`; addresses match BIP-86 KATs.

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
mod wif;

#[cfg(feature = "alloc")]
pub use deriver::{BtcAccount, Deriver};
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
pub use network::{Network, ParseNetworkError};
pub use types::{AddressType, ParseAddressTypeError};
#[cfg(feature = "alloc")]
pub use types::{DerivationPath, PathSegment};
