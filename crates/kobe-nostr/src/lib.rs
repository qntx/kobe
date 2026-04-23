//! Nostr wallet utilities for Kobe.
//!
//! Derives Nostr keys from a unified [`kobe_primitives::Wallet`] following
//! [NIP-06](https://nips.nostr.com/6) (BIP-32 path `m/44'/1237'/<account>'/0/0`)
//! and formats them as [NIP-19](https://nips.nostr.com/19) bech32 entities
//! (`nsec` for private keys, `npub` for x-only public keys).
//!
//! # Account vs index
//!
//! NIP-06 increments the *account* level of the BIP-32 path to obtain distinct
//! identities. Accordingly, [`Deriver::derive`] maps its `index` argument to
//! the `account` hardened segment.
//!
//! # Example
//!
//! ```no_run
//! use kobe_nostr::Deriver;
//! use kobe_primitives::Wallet;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let wallet = Wallet::from_mnemonic(
//!     "leader monkey parrot ring guide accident before fence cannon height naive bean",
//!     None,
//! )?;
//! let account = Deriver::new(&wallet).derive(0)?;
//! assert!(account.npub().starts_with("npub1"));
//! assert!(account.nsec().starts_with("nsec1"));
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod deriver;
mod error;

#[cfg(feature = "alloc")]
pub use deriver::{DerivedAccount, Deriver, NPUB_HRP, NSEC_HRP, NostrAccount};
pub use error::DeriveError;

/// A convenient Result type alias for kobe-nostr operations.
pub type Result<T> = core::result::Result<T, DeriveError>;
