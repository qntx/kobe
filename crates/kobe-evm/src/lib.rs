//! Ethereum HD wallet derivation and signing.
//!
//! Derives Ethereum (EIP-55 checksummed) addresses from a [`kobe_core::Wallet`]
//! seed following BIP-32/44, and signs transactions (legacy EIP-155, EIP-2930,
//! EIP-1559, EIP-7702), EIP-191 personal messages, EIP-712 typed data and
//! EIP-7702 authorizations.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod address;
mod deriver;
mod eip712;
mod rlp;
mod signer;

pub use address::to_checksum;
pub use deriver::{DerivationStyle, Deriver};
pub use kobe_core::{
    DerivedAccount, DerivedPublicKey, Error, ParseDerivationStyleError, RecoverableSignature,
};
pub use signer::{
    Signer, authorization_hash, encode_signature, encode_signed_transaction, parse_address,
    personal_message_hash, recover_address, transaction_hash, typed_data_hash,
};
