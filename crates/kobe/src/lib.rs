//! kobe — pure, offline HD wallet *generator*.
//!
//! BIP-39 mnemonic -> keys -> addresses for mainstream chains, as a
//! `no_std + alloc` library. No signing, no vault, no storage, no network.
//!
//! # Overview
//!
//! - [`Wallet`] holds a BIP-39 mnemonic + passphrase and the derived seed.
//! - A [`Chain`] implementation (one per coin, feature-gated under
//!   [`chains`]) exposes its [`Style`]s and derives [`Account`]s at
//!   [`DerivationPath`]s.
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
    feature = "cardano",
    feature = "bitcoin",
    feature = "cosmos",
    feature = "filecoin",
    feature = "kaspa",
    feature = "litecoin",
    feature = "spark",
    feature = "ton",
))]
mod macros;

#[cfg(any(
    feature = "cardano",
    feature = "bitcoin",
    feature = "cosmos",
    feature = "filecoin",
    feature = "kaspa",
    feature = "litecoin",
    feature = "spark",
    feature = "ton",
))]
pub(crate) use macros::option_enum;

mod account;
mod chain;
mod error;
mod path;
mod style;
mod wallet;

#[cfg(any(feature = "hd-bip32", feature = "hd-slip10", feature = "cardano"))]
pub(crate) mod encoding;
mod hd;

pub mod chains;
pub mod seedqr;

pub use account::{Account, SecretKey};
pub use chain::Chain;
pub use error::Error;
pub use path::{ChildIndex, DerivationPath};
pub use style::Style;
pub use wallet::{Wallet, WordCount};
