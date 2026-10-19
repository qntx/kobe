//! XRP Ledger (XRP): BIP-44 secp256k1 derivation, coin type 144.
//!
//! Classic `r…` addresses are `Base58Check` over the XRPL alphabet with
//! version `0x00`; the private key is plain hex.

use alloc::vec::Vec;

use crate::encoding::{base58::base58check_alphabet, hash::hash160, secret::hex_secret};
use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// XRPL base58 alphabet (differs from Bitcoin's).
const XRPL_ALPHABET: &bs58::Alphabet = bs58::Alphabet::RIPPLE;

/// XRPL account address version byte.
const VERSION: u8 = 0x00;

/// The XRP Ledger chain (secp256k1).
#[derive(Debug, Clone, Copy, Default)]
pub struct Xrpl;

impl Chain for Xrpl {
    fn styles(&self) -> Vec<Style> {
        Vec::from([
            Style::new("standard", "m/44'/144'/0'/0/{i}", "Xaman, Trust Wallet"),
            Style::new("ledger-live", "m/44'/144'/{i}'/0/0", "Ledger Live, OneKey"),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        let mut payload = Vec::with_capacity(21);
        payload.push(VERSION);
        payload.extend_from_slice(&hash160(&public_key));

        Ok(Account::new(
            path.clone(),
            base58check_alphabet(&payload, XRPL_ALPHABET),
            hex::encode(public_key),
            hex_secret(secret.as_slice()),
            SecretKey::Secp256k1(secret),
        ))
    }
}
