//! # Kobe-BTC - Bitcoin Wallet Support
//!
//! Bitcoin wallet implementation for the Kobe wallet library.
//! Provides private key, public key, address, HD wallets, and signing functionality.
//!
//! ## Features
//!
//! - **Private/Public Key Management**: secp256k1 key generation and manipulation
//! - **Multiple Address Formats**: P2PKH, P2SH, P2WPKH, P2WSH, P2TR (Taproot)
//! - **BIP-32 HD Wallets**: Hierarchical deterministic key derivation
//! - **BIP-39 Mnemonics**: Mnemonic phrase generation and seed derivation
//! - **WIF Import/Export**: Wallet Import Format support
//! - **Message Signing**: Bitcoin signed message support

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod address;
mod extended_key;
mod extended_public_key;
mod mnemonic;
mod network;
mod private_key;
mod public_key;
mod transaction;

pub use address::{AddressFormat, BtcAddress};
pub use extended_key::{BtcExtendedPrivateKey, ChildIndex};
pub use extended_public_key::BtcExtendedPublicKey;
pub use mnemonic::BtcMnemonic;
pub use network::Network;
pub use private_key::BtcPrivateKey;
pub use public_key::BtcPublicKey;
pub use transaction::{BtcTransaction, BtcTxId, p2pkh_script, p2wpkh_script};

// Re-export kobe core types and traits
pub use kobe::{
    Address, ExtendedPrivateKey as ExtendedPrivateKeyTrait,
    ExtendedPublicKey as ExtendedPublicKeyTrait, Mnemonic as MnemonicTrait, PrivateKey, PublicKey,
};
pub use kobe::{Error, Result, Signature};
