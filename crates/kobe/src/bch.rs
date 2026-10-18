//! Bitcoin Cash (BCH): BIP-44 derivation, coin type 145.
//!
//! Addresses are `CashAddr` `P2PKH` (`bitcoincash:q…`); the private key is
//! compressed WIF (version `0x80`).

use alloc::vec::Vec;

use crate::encoding::{base58::wif, cashaddr, hash::hash160};
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The Bitcoin Cash chain (`P2PKH` only).
#[derive(Debug, Clone, Copy, Default)]
pub struct BitcoinCash;

/// `CashAddr` version byte for a `P2PKH` output (type 0, 20-byte hash).
const VERSION: u8 = 0x00;

impl Chain for BitcoinCash {
    fn styles(&self) -> Vec<Style> {
        Vec::from([
            Style::new("standard", "m/44'/145'/0'/0/{i}", "Electron Cash"),
            Style::new("account", "m/44'/145'/{i}'/0/0", "Ledger Live, OneKey")
                .aliases(&["ledger-live"]),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        Ok(Account::new(
            path.clone(),
            cashaddr::encode("bitcoincash", VERSION, &hash160(&public_key)),
            hex::encode(public_key),
            wif(0x80, &secret)?,
            SecretKey::Secp256k1(secret),
        ))
    }
}
