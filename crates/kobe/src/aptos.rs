//! Aptos (APT): SLIP-10 ed25519 derivation, coin type 637.
//!
//! Address = `0x ‖ hex(sha3-256(pubkey ‖ 0x00))` (the `0x00` ed25519 scheme
//! flag); `private_key` uses the AIP-80 format `ed25519-priv-0x ‖ hex(sk)`.

use alloc::format;
use alloc::vec::Vec;

use sha3::{Digest as _, Sha3_256};

use crate::encoding::secret::hex_secret_prefixed;
use crate::hd::slip10;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The Aptos chain (hardened-only derivation).
#[derive(Debug, Clone, Copy, Default)]
pub struct Aptos;

impl Chain for Aptos {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "standard",
            "m/44'/637'/{i}'/0'/0'",
            "Petra, Pontem, OneKey, Ledger Live",
        )])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = slip10::Node::derive(wallet.seed(), path)?;
        let secret = node.secret_key();
        let public_key = node.public_key();

        let mut preimage = Vec::with_capacity(33);
        preimage.extend_from_slice(&public_key);
        preimage.push(0x00); // ed25519 scheme flag
        let hash: [u8; 32] = Sha3_256::digest(&preimage).into();

        Ok(Account::new(
            path.clone(),
            format!("0x{}", hex::encode(hash)),
            hex::encode(public_key),
            hex_secret_prefixed("ed25519-priv-0x", secret.as_slice()),
            SecretKey::Ed25519(secret),
        ))
    }
}
