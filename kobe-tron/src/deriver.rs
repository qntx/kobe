//! Tron address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::{String, ToString},
    vec,
};

use bip32::{DerivationPath, XPrv};
use k256::ecdsa::SigningKey;
use kobe::Wallet;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

use crate::Error;

/// Tron address deriver from a unified wallet seed.
///
/// Derives Tron addresses using BIP-44 path `m/44'/195'/0'/0/{index}`.
/// Tron addresses are base58check-encoded with a 0x41 mainnet prefix.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

/// A derived Tron address with associated key material.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DerivedAddress {
    /// Derivation path used (e.g. `m/44'/195'/0'/0/0`).
    pub path: String,
    /// Private key in hex format (zeroized on drop).
    pub private_key_hex: Zeroizing<String>,
    /// Uncompressed public key in hex format.
    pub public_key_hex: String,
    /// Base58check-encoded Tron address (starts with 'T').
    pub address: String,
}

impl<'a> Deriver<'a> {
    /// Create a new Tron deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive an address at the given account index.
    ///
    /// Uses BIP-44 path: `m/44'/195'/0'/0/{index}`
    pub fn derive(&self, index: u32) -> Result<DerivedAddress, Error> {
        let path = format!("m/44'/195'/0'/0/{index}");
        self.derive_path(&path)
    }

    /// Derive an address at a custom derivation path.
    pub fn derive_path(&self, path: &str) -> Result<DerivedAddress, Error> {
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| Error::Derivation(format!("invalid derivation path: {e}")))?;

        let derived = XPrv::derive_from_path(self.wallet.seed(), &derivation_path)
            .map_err(|e| Error::Derivation(format!("key derivation failed: {e}")))?;

        let signing_key: &SigningKey = derived.private_key();
        let verifying_key = signing_key.verifying_key();
        let pubkey_uncompressed = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey_uncompressed.as_bytes();

        // Keccak256 of the uncompressed public key (without 0x04 prefix byte), take last 20 bytes
        let hash = Keccak256::digest(&pubkey_bytes[1..]);
        let addr_bytes = &hash[12..];

        // Prepend 0x41 (Tron mainnet) and base58check encode
        let mut prefixed = vec![0x41u8];
        prefixed.extend_from_slice(addr_bytes);
        let address = bs58::encode(&prefixed).with_check().into_string();

        Ok(DerivedAddress {
            path: path.to_string(),
            private_key_hex: Zeroizing::new(hex::encode(signing_key.to_bytes())),
            public_key_hex: hex::encode(pubkey_bytes),
            address,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    #[test]
    fn derive_starts_with_t() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert!(
            derived.address.starts_with('T'),
            "Tron address should start with T, got: {}",
            derived.address
        );
    }

    #[test]
    fn derive_address_length() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.address.len(), 34);
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path, "m/44'/195'/0'/0/0");
    }

    #[test]
    fn deterministic() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_eq!(a1.address, a2.address);
    }

    #[test]
    fn different_indices_differ() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        let a0 = d.derive(0).unwrap();
        let a1 = d.derive(1).unwrap();
        assert_ne!(a0.address, a1.address);
    }

    #[test]
    fn base58check_roundtrip() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        let decoded = bs58::decode(&derived.address)
            .with_check(None)
            .into_vec()
            .unwrap();
        assert_eq!(decoded[0], 0x41);
        assert_eq!(decoded.len(), 21);
    }

    #[test]
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("pass")).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_ne!(a1.address, a2.address);
    }
}
