//! # Kobe-ETH - Ethereum Wallet Support
//!
//! Ethereum wallet implementation for the Kobe wallet library.
//! Provides private key, public key, address, HD wallets, and signing functionality.
//!
//! ## Features
//!
//! - **Private/Public Key Management**: secp256k1 key generation and manipulation
//! - **Address Generation**: EIP-55 checksummed addresses
//! - **BIP-32 HD Wallets**: Hierarchical deterministic key derivation
//! - **BIP-39 Mnemonics**: Mnemonic phrase generation and seed derivation
//! - **Message Signing**: EIP-191 and EIP-712 signing support

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::use_self,
    clippy::uninlined_format_args,
    clippy::return_self_not_must_use,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::many_single_char_names,
    clippy::redundant_closure_for_method_calls,
    clippy::option_if_let_else,
    clippy::needless_pass_by_value,
    clippy::format_push_string,
    clippy::unnecessary_wraps,
    clippy::implicit_clone,
    clippy::items_after_statements,
    clippy::struct_field_names,
    clippy::unreadable_literal,
    clippy::missing_fields_in_debug
)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod address;
mod eip191;
mod mnemonic;
mod network;
mod privkey;
mod pubkey;
mod transaction;
mod xpriv;
mod xpub;

pub use address::Address;
pub use bip39::Language;
pub use mnemonic::Mnemonic;
pub use network::Network;
pub use privkey::PrivateKey;
pub use pubkey::PublicKey;
pub use transaction::{Eip1559Transaction, Transaction, TxId};
pub use xpriv::ExtendedPrivateKey;
pub use xpub::ExtendedPublicKey;

// Re-export kobe core traits with trait suffix for clarity
pub use kobe::{
    Address as AddressTrait, ExtendedPrivateKey as ExtendedPrivateKeyTrait,
    ExtendedPublicKey as ExtendedPublicKeyTrait, Mnemonic as MnemonicTrait,
    PrivateKey as PrivateKeyTrait, PublicKey as PublicKeyTrait,
};
pub use kobe::{Error, Result, Signature};
