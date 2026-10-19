//! Spark: identity-key derivation and bech32m addresses.
//!
//! Path `m/8797555'/{i}'/0'` — purpose `8797555` as used by the official
//! SDK's `DefaultSparkKeysGenerator` — hardened BIP-32 secp256k1. The SDK
//! defaults to account index 1 on mainnet and 0 on regtest — encoded as
//! [`Style::start`]. Addresses are `bech32m(hrp, spark_address)` where the
//! payload is the `SparkAddress` protobuf with only field 1
//! (`identity_public_key`: `0x0a 0x21 ‖ 33-byte compressed pubkey`).
//!
//! # Caveats
//!
//! - The official Spark SDK derives its seed with `mnemonicToSeed(mnemonic)`
//!   and never applies a BIP-39 passphrase, so an address derived here with
//!   a passphrase is only reachable in the SDK by passing that seed
//!   directly.
//! - `private_key` is the identity key at `m/8797555'/{account}'/0'` only;
//!   Spark wallets also use signing/deposit/static-deposit/HTLC keys at
//!   `/1'` through `/4'`. Restore a Spark wallet from the mnemonic, not
//!   from this key.
//! - Spark is not Lightning: no Lightning node keys are derived, and Spark
//!   L1 deposit addresses depend on operator keys and cannot be derived
//!   offline.

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
            "Spark SDK",
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
