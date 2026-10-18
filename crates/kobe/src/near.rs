//! NEAR (NEAR): SLIP-10 ed25519 derivation, coin type 397.
//!
//! The implicit account id is `hex(pubkey)`; `public_key` and
//! `private_key` use the `ed25519:` base58 prefix convention
//! (`ed25519:base58(pk)` / `ed25519:base58(sk ‖ pk)`).

use alloc::format;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::hd::slip10;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The NEAR chain (hardened-only derivation).
#[derive(Debug, Clone, Copy, Default)]
pub struct Near;

impl Chain for Near {
    fn styles(&self) -> Vec<Style> {
        Vec::from([
            Style::new(
                "standard",
                "m/44'/397'/{i}'",
                "MyNearWallet, Meteor, near-cli, OneKey",
            ),
            Style::new("ledger-live", "m/44'/397'/0'/0'/{i}'", "Ledger Live"),
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
            hex::encode(public_key),
            format!("ed25519:{}", bs58::encode(public_key).into_string()),
            crate::encoding::secret::base58_secret_prefixed("ed25519:", &keypair)?,
            SecretKey::Ed25519(secret),
        ))
    }
}
