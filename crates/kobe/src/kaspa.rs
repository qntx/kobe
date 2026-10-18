//! Kaspa (KAS): BIP-44 derivation, coin type 111111.
//!
//! Addresses are cashaddr-style `kaspa:`/`kaspatest:` strings carrying the
//! 32-byte x-only schnorr public key (version byte 0).

use alloc::vec::Vec;

use crate::encoding::{cashaddr, secret::hex_secret};
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

/// Kaspa version byte for schnorr public-key addresses.
const VERSION: u8 = 0x00;

/// The Kaspa chain.
#[derive(Debug, Clone, Copy, Default)]
pub struct Kaspa {
    /// Target network.
    pub network: Network,
}

impl Kaspa {
    /// A `Kaspa` chain for `network`.
    #[must_use]
    pub const fn new(network: Network) -> Self {
        Self { network }
    }
}

impl Chain for Kaspa {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "standard",
            "m/44'/111111'/0'/0/{i}",
            "Kaspium, KasWare, OneKey",
        )])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        // Kaspa addresses carry the 32-byte x-only schnorr public key.
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(public_key.split_at(1).1);

        Ok(Account::new(
            path.clone(),
            cashaddr::encode(self.network.prefix(), VERSION, &x_only),
            hex::encode(x_only),
            hex_secret(secret.as_slice()),
            SecretKey::Secp256k1(secret),
        ))
    }
}
