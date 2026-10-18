//! Nostr: NIP-06 key derivation at `m/44'/1237'/{i}'/0/0`.
//!
//! `address` is the NIP-19 `npub…` (bech32 over the x-only schnorr public
//! key), `public_key` the x-only hex, and `private_key` the `nsec…`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::hd::bip32;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// The Nostr chain (NIP-06).
#[derive(Debug, Clone, Copy, Default)]
pub struct Nostr;

/// Bech32 encode `data` under `hrp` (NIP-19 entities).
fn npub_encode(hrp: &str, data: &[u8]) -> Result<String, Error> {
    bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked(hrp), data)
        .map_err(|e| Error::InvalidKey(format!("bech32: {e}")))
}

impl Chain for Nostr {
    fn styles(&self) -> Vec<Style> {
        Vec::from([Style::new(
            "nip06",
            "m/44'/1237'/{i}'/0/0",
            "Damus, Amethyst, Primal, Iris, OneKey",
        )])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = bip32::Node::derive(wallet.seed(), path)?;
        let secret = node.private_key();
        let public_key = node.public_key();

        // Nostr identities use the 32-byte x-only schnorr public key.
        let x_only = public_key.split_at(1).1;

        Ok(Account::new(
            path.clone(),
            npub_encode("npub", x_only)?,
            hex::encode(x_only),
            Zeroizing::new(npub_encode("nsec", secret.as_slice())?),
            SecretKey::Secp256k1(secret),
        ))
    }
}
