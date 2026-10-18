//! Litecoin (LTC): BIP-44/49/84 derivation, coin type 2.
//!
//! `P2PKH` (0x30) and `P2SH-P2WPKH` (0x32) are `Base58Check`, `P2WPKH` is
//! segwit-v0 bech32 with the `ltc` HRP. The private key is compressed WIF
//! (version `0xb0`).

use alloc::format;
use alloc::vec::Vec;

use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet, encoding};

crate::option_enum! {
    /// Litecoin address kind (output type).
    pub enum Kind {
        /// Legacy pay-to-public-key-hash (`L…`).
        P2pkh = "p2pkh",
        /// Segwit wrapped in P2SH (`M…`).
        P2shP2wpkh = "p2sh-p2wpkh",
        /// Native segwit v0 pay-to-witness-public-key-hash (`ltc1q…`).
        #[default]
        P2wpkh = "p2wpkh",
    }
}

impl Kind {
    /// BIP purpose: 44/49/84.
    #[must_use]
    pub const fn purpose(self) -> u32 {
        match self {
            Self::P2pkh => 44,
            Self::P2shP2wpkh => 49,
            Self::P2wpkh => 84,
        }
    }
}

/// The `ltc` bech32 human-readable part.
const HRP_LTC: bech32::Hrp = bech32::Hrp::parse_unchecked("ltc");

/// The Litecoin chain.
#[derive(Debug, Clone, Copy, Default)]
pub struct Litecoin {
    /// Address kind.
    pub kind: Kind,
}

impl Litecoin {
    /// A `Litecoin` chain emitting `kind` addresses.
    #[must_use]
    pub const fn new(kind: Kind) -> Self {
        Self { kind }
    }
}

impl Chain for Litecoin {
    fn styles(&self) -> Vec<Style> {
        let purpose = self.kind.purpose();
        Vec::from([
            Style::new(
                "standard",
                format!("m/{purpose}'/2'/0'/0/{{i}}"),
                "Sparrow, Electrum-LTC, LoafWallet",
            ),
            Style::new(
                "account",
                format!("m/{purpose}'/2'/{{i}}'/0/0"),
                "Ledger Live, Trezor Suite, OneKey",
            )
            .aliases(&["ledger-live"]),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        let address = match self.kind {
            Kind::P2pkh => encoding::segwit::p2pkh(0x30, &public_key),
            Kind::P2shP2wpkh => encoding::segwit::p2sh_p2wpkh(0x32, &public_key),
            Kind::P2wpkh => encoding::segwit::p2wpkh(HRP_LTC, &public_key)?,
        };

        Ok(Account::new(
            path.clone(),
            address,
            hex::encode(public_key),
            encoding::base58::wif(0xb0, &secret)?,
            SecretKey::Secp256k1(secret),
        ))
    }
}
