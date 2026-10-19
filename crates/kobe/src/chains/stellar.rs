//! Stellar (XLM): SEP-0005 SLIP-10 ed25519 derivation at `m/44'/148'/{i}'`.
//!
//! Addresses are `StrKey` `G…` account ids; `private_key` is the `S…`
//! secret seed. `StrKey` is `base32(version ‖ payload ‖ crc16-xmodem-le)`
//! with no padding — implemented in `crate::encoding::strkey`.

use alloc::vec::Vec;

use crate::encoding::strkey;
use crate::hd::slip10;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The Stellar chain (SEP-0005).
#[derive(Debug, Clone, Copy, Default)]
pub struct Stellar;

impl Chain for Stellar {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "sep5",
            "m/44'/148'/{i}'",
            "Lobstr, Freighter, Ledger Live, OneKey, Trust Wallet",
        )])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = slip10::Node::derive(wallet.seed(), path)?;
        let secret = node.secret_key();
        let public_key = node.public_key();

        Ok(Account::new(
            path.clone(),
            strkey::encode_public(strkey::VERSION_PUBLIC, &public_key),
            hex::encode(public_key),
            strkey::encode_secret(strkey::VERSION_SECRET, &secret),
            SecretKey::Ed25519(secret),
        ))
    }
}
