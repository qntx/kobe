//! Solana (SOL): SLIP-10 ed25519 (hardened-only) derivation.
//!
//! Address = base58 of the public key; `private_key` = base58 of the 64-byte
//! `sk ‖ pk` keypair used by Phantom, Solflare, `solana-keygen`, etc.
//!
//! `root` is Ledger Live's `solanaMain` derivation mode: a single,
//! non-iterating account at `m/44'/501'`.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::hd::slip10;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The Solana chain (coin type 501, hardened-only derivation).
#[derive(Debug, Clone, Copy, Default)]
pub struct Solana;

impl Chain for Solana {
    fn styles(&self) -> Vec<Style> {
        Vec::from([
            Style::new(
                "bip44-change",
                "m/44'/501'/{i}'/0'",
                "Phantom, Solflare, Backpack, OneKey, Ledger Live, Solana CLI (?key=i/0)",
            )
            .aliases(&["phantom"]),
            Style::new("bip44", "m/44'/501'/{i}'", "Ledger Live, Trust Wallet").aliases(&["trust"]),
            Style::new("root", "m/44'/501'", "Ledger Live (first account)"),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = slip10::Node::derive(wallet.seed(), path)?;
        let secret = node.secret_key();
        let public_key = node.public_key();

        let mut keypair = Zeroizing::new(Vec::with_capacity(64));
        keypair.extend_from_slice(secret.as_slice());
        keypair.extend_from_slice(&public_key);

        Ok(Account::new(
            path.clone(),
            bs58::encode(public_key).into_string(),
            hex::encode(public_key),
            crate::encoding::secret::base58_secret(&keypair)?,
            SecretKey::Ed25519(secret),
        ))
    }
}
