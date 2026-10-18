//! TRON (TRX): BIP-44 derivation, coin type 195.
//!
//! Addresses are `Base58Check(0x41 ‖ keccak256(uncompressed[1..])[12..])`
//! (`T…`); the private key is plain hex without a `0x` prefix.

use alloc::vec::Vec;

use crate::encoding::{base58::base58check_versioned, hash::eth_address_bytes, secret::hex_secret};
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The TRON chain.
#[derive(Debug, Clone, Copy, Default)]
pub struct Tron;

impl Chain for Tron {
    fn styles(&self) -> Vec<Style> {
        Vec::from([
            Style::new(
                "standard",
                "m/44'/195'/0'/0/{i}",
                "TronLink, Trust Wallet, OneKey",
            ),
            Style::new("ledger-live", "m/44'/195'/{i}'/0/0", "Ledger Live"),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key_uncompressed();

        Ok(Account::new(
            path.clone(),
            base58check_versioned(0x41, &eth_address_bytes(&public_key)),
            hex::encode(public_key),
            hex_secret(secret.as_slice()),
            SecretKey::Secp256k1(secret),
        ))
    }
}
