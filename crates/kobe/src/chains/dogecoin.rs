//! Dogecoin (DOGE): BIP-44 `P2PKH` derivation, coin type 3.
//!
//! Addresses are `Base58Check` with version `0x1e` (`D…`); the private key
//! is compressed WIF with version `0x9e`.

use alloc::vec::Vec;

use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet, encoding};

/// The Dogecoin chain (`P2PKH` only).
#[derive(Debug, Clone, Copy, Default)]
pub struct Dogecoin;

impl Chain for Dogecoin {
    fn styles(&self) -> Vec<Style> {
        Vec::from([
            Style::new("standard", "m/44'/3'/0'/0/{i}", "Trust Wallet"),
            Style::new(
                "account",
                "m/44'/3'/{i}'/0/0",
                "Ledger Live, Trezor Suite, OneKey",
            )
            .aliases(&["ledger-live"]),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        Ok(Account::new(
            path.clone(),
            encoding::segwit::p2pkh(0x1e, &public_key),
            hex::encode(public_key),
            encoding::base58::wif(0x9e, &secret)?,
            SecretKey::Secp256k1(secret),
        ))
    }
}
