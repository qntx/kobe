//! Casper (CSPR): BIP-44 derivation, coin type 506.
//!
//! The address is hex of `02 ‖ compressed pubkey`: the `02` secp256k1
//! algorithm tag followed by the 33-byte compressed key.
//! `extra.account_hash` is
//! `account-hash-‖hex(blake2b-256("secp256k1" ‖ 0x00 ‖ compressed))`.

use alloc::format;
use alloc::vec::Vec;

use crate::encoding::{hash::blake2b_256, secret::hex_secret};
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The Casper chain (secp256k1).
#[derive(Debug, Clone, Copy, Default)]
pub struct Casper;

impl Chain for Casper {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "standard",
            "m/44'/506'/0'/0/{i}",
            "Casper Wallet, Ledger Live",
        )])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        let mut preimage = Vec::with_capacity(9 + 1 + 33);
        preimage.extend_from_slice(b"secp256k1");
        preimage.push(0x00);
        preimage.extend_from_slice(&public_key);
        let account_hash = format!("account-hash-{}", hex::encode(blake2b_256(&preimage)));

        let mut account = Account::new(
            path.clone(),
            format!("02{}", hex::encode(public_key)),
            hex::encode(public_key),
            hex_secret(secret.as_slice()),
            SecretKey::Secp256k1(secret),
        );
        account.extra.push(("account_hash", account_hash));
        Ok(account)
    }
}
