//! Tron address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec};

pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet};
use sha3::{Digest, Keccak256};

use crate::DeriveError;

/// Tron address deriver from a unified wallet seed.
///
/// Derives Tron addresses using BIP-44 path `m/44'/195'/0'/0/{index}`.
/// Tron addresses are base58check-encoded with a 0x41 mainnet prefix.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Tron deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Internal derivation at arbitrary path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
        let uncompressed = key.uncompressed_pubkey();

        let hash = Keccak256::digest(&uncompressed[1..]);
        let (_, addr_bytes) = hash.split_at(12);
        let mut prefixed = vec![0x41u8];
        prefixed.extend_from_slice(addr_bytes);
        let address = bs58::encode(&prefixed).with_check().into_string();

        Ok(DerivedAccount::new(
            String::from(path),
            key.private_key_bytes(),
            uncompressed.to_vec(),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(&format!("m/44'/195'/0'/0/{index}"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions")]
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
            derived.address().starts_with('T'),
            "Tron address should start with T, got: {}",
            derived.address()
        );
    }

    #[test]
    fn derive_address_length() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.address().len(), 34);
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path(), "m/44'/195'/0'/0/0");
    }

    #[test]
    fn deterministic() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_eq!(a1.address(), a2.address());
    }

    #[test]
    fn different_indices_differ() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        let a0 = d.derive(0).unwrap();
        let a1 = d.derive(1).unwrap();
        assert_ne!(a0.address(), a1.address());
    }

    #[test]
    fn base58check_roundtrip() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        let decoded = bs58::decode(derived.address())
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
        assert_ne!(a1.address(), a2.address());
    }

    #[test]
    fn kat_tron_index0() {
        // Cross-verified with Python coincurve + keccak256 + base58check(0x41 prefix)
        let wallet = test_wallet();
        let a = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(a.address(), "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
    }
}
