//! Cosmos SDK chains: BIP-32 secp256k1 + bech32 addresses.
//!
//! Each [`Preset`] fixes a BIP-44 coin type and default bech32 HRP; an
//! optional `hrp` override repoints the address prefix without changing the
//! derivation. Ethereum-style presets (`injective`, `evmos`) hash the
//! uncompressed key with keccak256 instead of hash160.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::encoding::{
    hash::{eth_address_bytes, hash160},
    secret::hex_secret,
};
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

crate::option_enum! {
    /// A supported Cosmos SDK chain preset (coin type + default HRP + hashing).
    pub enum Preset {
        /// Cosmos Hub (`cosmos`, coin type 118).
        #[default]
        Cosmos = "cosmos",
        /// Osmosis (`osmo`, coin type 118).
        Osmosis = "osmosis",
        /// Celestia (`celestia`, coin type 118).
        Celestia = "celestia",
        /// dYdX (`dydx`, coin type 118).
        Dydx = "dydx",
        /// Sei (`sei`, coin type 118).
        Sei = "sei",
        /// Akash (`akash`, coin type 118).
        Akash = "akash",
        /// Terra (`terra`, coin type 330).
        Terra = "terra",
        /// Secret Network (`secret`, coin type 529).
        Secret = "secret",
        /// Kava (`kava`, coin type 459).
        Kava = "kava",
        /// Injective (`inj`, coin type 60, keccak256 hashing).
        Injective = "injective",
        /// Evmos (`evmos`, coin type 60, keccak256 hashing).
        Evmos = "evmos",
    }
}

impl Preset {
    /// BIP-44 coin type.
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Terra => 330,
            Self::Secret => 529,
            Self::Kava => 459,
            Self::Injective | Self::Evmos => 60,
            _ => 118,
        }
    }

    /// Default bech32 human-readable part.
    #[must_use]
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Cosmos => "cosmos",
            Self::Osmosis => "osmo",
            Self::Celestia => "celestia",
            Self::Dydx => "dydx",
            Self::Sei => "sei",
            Self::Akash => "akash",
            Self::Terra => "terra",
            Self::Secret => "secret",
            Self::Kava => "kava",
            Self::Injective => "inj",
            Self::Evmos => "evmos",
        }
    }

    /// Whether the preset uses Ethereum-style `keccak256(uncompressed[1..])`
    /// addressing (`injective`, `evmos`).
    #[must_use]
    pub const fn is_eth(self) -> bool {
        matches!(self, Self::Injective | Self::Evmos)
    }
}

/// A Cosmos SDK chain: preset plus an optional bech32 HRP override.
#[derive(Debug, Clone, Default)]
pub struct Cosmos {
    /// Chain preset (coin type, default HRP, hashing rule).
    pub preset: Preset,
    /// Optional bech32 HRP override (`None` = the preset's default).
    pub hrp: Option<String>,
}

impl Cosmos {
    /// A `Cosmos` chain for `preset` with its default HRP.
    #[must_use]
    pub const fn new(preset: Preset) -> Self {
        Self { preset, hrp: None }
    }
}

impl Chain for Cosmos {
    fn styles(&self) -> Vec<Style> {
        let coin = self.preset.coin_type();
        Vec::from([
            Style::new(
                "standard",
                format!("m/44'/{coin}'/0'/0/{{i}}"),
                "Keplr, Leap, Cosmostation, OneKey",
            ),
            Style::new(
                "ledger-live",
                format!("m/44'/{coin}'/{{i}}'/0/0"),
                "Ledger Live",
            ),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let hrp = bech32::Hrp::parse(self.hrp.as_deref().unwrap_or_else(|| self.preset.hrp()))
            .map_err(|e| Error::InvalidValue(format!("invalid hrp: {e}")))?;

        let (payload, public_key) = if self.preset.is_eth() {
            let uncompressed = node.public_key_uncompressed();
            (eth_address_bytes(&uncompressed), hex::encode(uncompressed))
        } else {
            let compressed = node.public_key();
            (hash160(&compressed), hex::encode(compressed))
        };
        let address = bech32::encode::<bech32::Bech32>(hrp, &payload)
            .map_err(|e| Error::InvalidKey(format!("bech32: {e}")))?;

        Ok(Account::new(
            path.clone(),
            address,
            public_key,
            hex_secret(secret.as_slice()),
            SecretKey::Secp256k1(secret),
        ))
    }
}
