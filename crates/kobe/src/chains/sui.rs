//! Sui (SUI): SLIP-10 ed25519 derivation, coin type 784.
//!
//! Address = `0x ‖ hex(blake2b-256(0x00 ‖ pubkey))` (the `0x00` ed25519
//! scheme flag); `private_key` = `suiprivkey1…` (bech32 over `0x00 ‖ sk`).

use alloc::format;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::encoding::hash::blake2b_256;
use crate::hd::slip10;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// Sui ed25519 signature-scheme flag.
const FLAG: u8 = 0x00;

/// The Sui chain (hardened-only derivation).
#[derive(Debug, Clone, Copy, Default)]
pub struct Sui;

impl Chain for Sui {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "standard",
            "m/44'/784'/{i}'/0'/0'",
            "Slush, Suiet, OneKey, Ledger Live, Trust Wallet",
        )])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = slip10::Node::derive(wallet.seed(), path)?;
        let secret = node.secret_key();
        let public_key = node.public_key();

        let mut preimage = Vec::with_capacity(33);
        preimage.push(FLAG);
        preimage.extend_from_slice(&public_key);

        let mut private_key = Zeroizing::new(Vec::with_capacity(33));
        private_key.push(FLAG);
        private_key.extend_from_slice(secret.as_slice());
        let hrp = bech32::Hrp::parse_unchecked("suiprivkey");

        Ok(Account::new(
            path.clone(),
            format!("0x{}", hex::encode(blake2b_256(&preimage))),
            hex::encode(public_key),
            Zeroizing::new(
                bech32::encode::<bech32::Bech32>(hrp, &private_key)
                    .map_err(|e| Error::InvalidKey(format!("bech32: {e}")))?,
            ),
            SecretKey::Ed25519(secret),
        ))
    }
}
