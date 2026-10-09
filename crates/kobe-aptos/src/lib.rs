//! Aptos address derivation from a [`kobe_core::Wallet`].
//!
//! Uses SLIP-10 Ed25519 at path `m/44'/637'/{index}'/0'/0'`.
//! Address = `0x` + hex(SHA3-256(0x00 || pubkey)).

#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_extern_crates, reason = "needed for alloc re-export in no_std")]
extern crate alloc;

mod deriver;

pub use deriver::Deriver;
pub use kobe_core::{DerivedAccount, DerivedPublicKey, Error};
