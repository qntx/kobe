//! Arweave ECDSA (secp256k1) wallet utilities for Kobe.
//!
//! Offline HD derivation only: BIP-44 coin type **472**, compressed public key,
//! address = `Base64URL(SHA-256(compressed_pk))`. RSA and transaction signing
//! are out of scope (see crate docs on [`Deriver`]).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::{Deriver, address_from_compressed_pubkey, owner_from_compressed_pubkey};
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
