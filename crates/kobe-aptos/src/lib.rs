//! Aptos address derivation from a [`kobe_primitives::Wallet`].
//!
//! Uses SLIP-10 Ed25519 at path `m/44'/637'/{index}'/0'/0'`.
//! Address = `0x` + hex(SHA3-256(0x00 || pubkey)).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
#[allow(unused_extern_crates, reason = "needed for alloc re-export in no_std")]
extern crate alloc;

mod deriver;

#[cfg(feature = "alloc")]
pub use deriver::Deriver;
pub use kobe_primitives::{DeriveError, DerivedAccount, DerivedPublicKey};
