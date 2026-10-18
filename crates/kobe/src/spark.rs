//! Spark: identity-key derivation and bech32m addresses.
//!
//! Path `m/8797555'/{i}'/0'` (purpose `8797555`, from `SHA-256("spark")`),
//! hardened BIP-32 secp256k1. The official SDK defaults to account index 1
//! on mainnet and 0 on regtest — encoded as [`Style::start`]. Addresses are
//! `bech32m(hrp, 0x0a ‖ 0x21 ‖ compressed pubkey)` (a pseudo-protobuf field
//! wrapper), without the BIP-173 90-character limit.

use alloc::format;
use alloc::vec::Vec;

use crate::encoding::secret::hex_secret;
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// Spark-specific BIP-32 purpose.
pub const SPARK_PURPOSE: u32 = 8_797_555;

crate::option_enum! {
    /// Spark network selection (the official SDK supports only these two).
    pub enum Network {
        /// Spark mainnet (`spark1…`, default account index 1).
        #[default]
        Mainnet = "mainnet",
        /// Spark regtest (`sparkrt1…`, default account index 0).
        Regtest = "regtest",
    }
}

impl Network {
    /// Bech32m human-readable part.
    #[must_use]
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "spark",
            Self::Regtest => "sparkrt",
        }
    }

    /// Default account index in the official Spark SDK.
    #[must_use]
    pub const fn default_account(self) -> u32 {
        match self {
            Self::Mainnet => 1,
            Self::Regtest => 0,
        }
    }
}

/// The Spark chain (identity keys).
#[derive(Debug, Clone, Copy, Default)]
pub struct Spark {
    /// Target network.
    pub network: Network,
}

impl Spark {
    /// A `Spark` chain for `network`.
    #[must_use]
    pub const fn new(network: Network) -> Self {
        Self { network }
    }
}

impl Chain for Spark {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "standard",
            format!("m/{SPARK_PURPOSE}'/{{i}}'/0'"),
            "Spark wallet SDK",
        )
        .start(self.network.default_account())])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        // Pseudo-protobuf wrapper: field 1, wire type 2, length 33.
        let mut payload = Vec::with_capacity(35);
        payload.push(0x0a);
        payload.push(0x21);
        payload.extend_from_slice(&public_key);

        let hrp = bech32::Hrp::parse_unchecked(self.network.hrp());
        let address = bech32::encode::<bech32::Bech32m>(hrp, &payload)
            .map_err(|e| Error::InvalidKey(format!("bech32m: {e}")))?;

        Ok(Account::new(
            path.clone(),
            address,
            hex::encode(public_key),
            hex_secret(secret.as_slice()),
            SecretKey::Secp256k1(secret),
        ))
    }
}
