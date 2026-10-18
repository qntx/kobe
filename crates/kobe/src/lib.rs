//! kobe — pure, offline HD wallet *generator*.
//!
//! BIP-39 mnemonic -> keys -> addresses for mainstream chains, as a
//! `no_std + alloc` library. No signing, no vault, no storage, no network.
//!
//! # Overview
//!
//! - [`Wallet`] holds a BIP-39 mnemonic + passphrase and the derived seed.
//! - A [`Chain`] implementation (one per coin, feature-gated) exposes its
//!   [`Style`]s and derives [`Account`]s at [`DerivationPath`]s.
//! - [`Account`] carries the address, public key, wallet-import private key
//!   string, and the raw [`SecretKey`].

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(
        unused_crate_dependencies,
        reason = "dev-dependencies are used only by feature-gated test modules"
    )
)]

extern crate alloc;

#[cfg(any(
    feature = "ada",
    feature = "btc",
    feature = "cosmos",
    feature = "fil",
    feature = "kaspa",
    feature = "ltc",
    feature = "spark",
    feature = "ton",
))]
mod macros;

#[cfg(any(
    feature = "ada",
    feature = "btc",
    feature = "cosmos",
    feature = "fil",
    feature = "kaspa",
    feature = "ltc",
    feature = "spark",
    feature = "ton",
))]
pub(crate) use macros::option_enum;

mod chain;
mod error;
mod path;
mod style;
mod wallet;

#[cfg(any(feature = "hd-bip32", feature = "hd-slip10", feature = "ada"))]
pub(crate) mod encoding;
mod hd;

#[cfg(feature = "ada")]
pub mod ada;
#[cfg(feature = "aptos")]
pub mod aptos;
#[cfg(feature = "bch")]
pub mod bch;
#[cfg(feature = "btc")]
pub mod btc;
#[cfg(feature = "casper")]
pub mod casper;
#[cfg(feature = "cosmos")]
pub mod cosmos;
#[cfg(feature = "doge")]
pub mod doge;
#[cfg(feature = "evm")]
pub mod evm;
#[cfg(feature = "fil")]
pub mod fil;
#[cfg(feature = "kaspa")]
pub mod kaspa;
#[cfg(feature = "ltc")]
pub mod ltc;
#[cfg(feature = "near")]
pub mod near;
#[cfg(feature = "nostr")]
pub mod nostr;
#[cfg(feature = "sol")]
pub mod sol;
#[cfg(feature = "spark")]
pub mod spark;
#[cfg(feature = "sui")]
pub mod sui;
#[cfg(feature = "ton")]
pub mod ton;
#[cfg(feature = "tron")]
pub mod tron;
#[cfg(feature = "xlm")]
pub mod xlm;
#[cfg(feature = "xrp")]
pub mod xrp;

pub use chain::{Account, Chain, SecretKey};
pub use error::Error;
pub use path::{ChildIndex, DerivationPath};
pub use style::Style;
pub use wallet::{Wallet, WordCount};
