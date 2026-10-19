//! Kaspa (KAS): BIP-44 derivation, coin type 111111.
//!
//! Addresses are cashaddr-style `kaspa:`/`kaspatest:` strings carrying a
//! 32-byte x-only schnorr public key (version byte 0). The `standard`
//! encoding carries the derived key as-is; `onekey` reproduces the `OneKey`
//! account type (`publicKeyFromOriginPubkey`), whose address carries the
//! BIP-341 key-path-tweaked key `x(Q)` while `private_key` stays the
//! untweaked derived key (the wallet exports the raw key via
//! `privateKeyFromBuffer`).

use alloc::vec::Vec;

use crate::encoding::{cashaddr, secret::hex_secret, taproot};
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

crate::option_enum! {
    /// Kaspa network selection.
    pub enum Network {
        /// Kaspa mainnet (`kaspa:`).
        #[default]
        Mainnet = "mainnet",
        /// Kaspa testnet (`kaspatest:`).
        Testnet = "testnet",
    }
}

impl Network {
    /// Address prefix.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Mainnet => "kaspa",
            Self::Testnet => "kaspatest",
        }
    }
}

crate::option_enum! {
    /// Address encoding: which public key the address carries.
    pub enum Encoding {
        /// Derived x-only schnorr public key (`kaspa:q…`).
        #[default]
        Standard = "standard",
        /// The `OneKey` tweaked key: `x(Q)` for `Q = lift_x(P) + tweak·G`.
        Onekey = "onekey",
    }
}

/// Kaspa version byte for schnorr public-key addresses.
const VERSION: u8 = 0x00;

/// The Kaspa chain.
#[derive(Debug, Clone, Copy, Default)]
pub struct Kaspa {
    /// Target network.
    pub network: Network,
    /// Address encoding.
    pub encoding: Encoding,
}

impl Kaspa {
    /// A `Kaspa` chain for `network` and `encoding`.
    #[must_use]
    pub const fn new(network: Network, encoding: Encoding) -> Self {
        Self { network, encoding }
    }
}

impl Chain for Kaspa {
    fn styles(&self) -> Vec<Style> {
        let wallets = match self.encoding {
            Encoding::Standard => "Kaspa NG, Kaspium, KasWare, OneKey (Kaspa Official)",
            Encoding::Onekey => "OneKey (default Kaspa account)",
        };
        Vec::from([Style::new("standard", "m/44'/111111'/0'/0/{i}", wallets)])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        // Kaspa addresses carry a 32-byte x-only schnorr public key.
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(public_key.split_at(1).1);
        let address_key = match self.encoding {
            Encoding::Standard => x_only,
            Encoding::Onekey => taproot::tweaked_x(&x_only)?,
        };

        Ok(Account::new(
            path.clone(),
            cashaddr::encode(self.network.prefix(), VERSION, &address_key),
            hex::encode(address_key),
            hex_secret(secret.as_slice()),
            SecretKey::Secp256k1(secret),
        ))
    }
}
