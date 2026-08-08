//! Casper Network wallet utilities for Kobe.
//!
//! Offline HD derivation for **CSPR** (SLIP-44 coin type `506`) with dual
//! signature algorithms:
//!
//! | Algorithm | Default path | Curve | Kobe primitive |
//! | --- | --- | --- | --- |
//! | [`KeyAlgo::Secp256k1`] (default) | `m/44'/506'/0'/0/{i}` | secp256k1 | BIP-32 |
//! | [`KeyAlgo::Ed25519`] | `m/44'/506'/0'/0'/{i}'` | Ed25519 | SLIP-10 |
//!
//! # Address encoding
//!
//! The primary [`DerivedAccount::address`] is the Casper **`AccountHash`**
//! display form `account-hash-` + 64 lowercase hex digits.
//!
//! Per [`casper-types`](https://github.com/casper-network/casper-node)
//! `AccountHash::from_public_key`, the `BLAKE2b`-256 preimage is **not** the
//! tag-prefixed public-key serialization. It is:
//!
//! ```text
//! algorithm_name_ascii || 0x00 || raw_public_key_bytes
//! ```
//!
//! where `algorithm_name` is the lowercase ASCII string `"secp256k1"` or
//! `"ed25519"`, and `raw_public_key_bytes` is the 33-byte compressed `SEC1`
//! secp256k1 key or the 32-byte Ed25519 key (no algorithm tag byte).
//!
//! The algorithm-tagged public-key hex used in Casper serialization /
//! CEP-57 contexts (`0x01 ‖ ed25519` or `0x02 ‖ secp compressed`) is
//! exposed separately on [`CasperAccount::tagged_public_key_hex`].
//!
//! # Example
//!
//! ```no_run
//! use kobe_casper::{Deriver, KeyAlgo};
//! use kobe_primitives::{Derive, Wallet};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = Wallet::from_mnemonic(
//!     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//!     None,
//! )?;
//! let account = Deriver::new(&wallet).derive(0)?;
//! assert!(account.address().starts_with("account-hash-"));
//! assert_eq!(account.algo(), KeyAlgo::Secp256k1);
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod address;
#[cfg(feature = "alloc")]
mod deriver;
#[cfg(feature = "alloc")]
mod key_algo;

#[cfg(feature = "alloc")]
pub use address::{
    ACCOUNT_HASH_PREFIX, ED25519_TAG, SECP256K1_TAG, account_hash_ed25519, account_hash_secp256k1,
    format_account_hash, tagged_public_key_hex,
};
#[cfg(feature = "alloc")]
pub use deriver::{CasperAccount, Deriver};
#[cfg(feature = "alloc")]
pub use key_algo::KeyAlgo;
pub use kobe_primitives::{
    DeriveError, DerivedAccount, DerivedPublicKey, ParseDerivationStyleError,
};
