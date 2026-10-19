//! Filecoin (FIL): BIP-44 secp256k1 derivation, coin type 461.
//!
//! `f1…`/`t1…` addresses carry `blake2b-160(uncompressed pubkey)` with a
//! `blake2b-32` checksum, base32-lowercase encoded. The private key is the
//! hex of the Lotus export JSON `{"Type":"secp256k1","PrivateKey":"<b64>"}`.

use alloc::format;
use alloc::vec::Vec;

use blake2::Digest as _;
use zeroize::Zeroizing;

use crate::encoding::{
    base32_lower,
    hash::blake2b_160,
    secret::{hex_secret, push_base64},
};
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

crate::option_enum! {
    /// Filecoin network selection.
    pub enum Network {
        /// Mainnet (`f1…`).
        #[default]
        Mainnet = "mainnet",
        /// Testnet (`t1…`).
        Testnet = "testnet",
    }
}

impl Network {
    /// Address prefix: `f` mainnet / `t` testnet.
    #[must_use]
    pub const fn prefix(self) -> char {
        match self {
            Self::Mainnet => 'f',
            Self::Testnet => 't',
        }
    }
}

/// The Filecoin chain (secp256k1 protocol `1` addresses).
#[derive(Debug, Clone, Copy, Default)]
pub struct Filecoin {
    /// Target network.
    pub network: Network,
}

impl Filecoin {
    /// A `Filecoin` chain for `network`.
    #[must_use]
    pub const fn new(network: Network) -> Self {
        Self { network }
    }
}

impl Chain for Filecoin {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "standard",
            "m/44'/461'/0'/0/{i}",
            "Glif, Ledger Live, OneKey, Trust Wallet",
        )])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key_uncompressed();

        let payload = blake2b_160(&public_key);
        let mut checksum_input = Vec::with_capacity(21);
        checksum_input.push(1);
        checksum_input.extend_from_slice(&payload);
        let checksum = blake2::Blake2b::<blake2::digest::consts::U4>::digest(&checksum_input);

        let mut body = Vec::with_capacity(24);
        body.extend_from_slice(&payload);
        body.extend_from_slice(&checksum);

        // Lotus export JSON assembled in a zeroized buffer.
        let mut export = Zeroizing::new(alloc::string::String::with_capacity(96));
        export.push_str("{\"Type\":\"secp256k1\",\"PrivateKey\":\"");
        push_base64(&mut export, secret.as_slice());
        export.push_str("\"}");

        Ok(Account::new(
            path.clone(),
            format!("{}1{}", self.network.prefix(), base32_lower(&body)),
            hex::encode(public_key),
            hex_secret(export.as_bytes()),
            SecretKey::Secp256k1(secret),
        ))
    }
}
