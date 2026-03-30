//! Sui address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use ed25519_dalek::VerifyingKey;
use kobe::Wallet;
use zeroize::Zeroizing;

use crate::Error;
use crate::slip10::DerivedKey;

/// Ed25519 signature scheme flag used by Sui.
const ED25519_FLAG: u8 = 0x00;

/// Sui address deriver from a unified wallet seed.
///
/// Derives Sui addresses using SLIP-10 Ed25519 at path `m/44'/784'/{index}'/0'/0'`.
/// Address = `0x` + hex(BLAKE2b-256(0x00 || pubkey)).
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

/// A derived Sui address with associated key material.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DerivedAddress {
    /// Derivation path used (e.g. `m/44'/784'/0'/0'/0'`).
    pub path: String,
    /// Private key in hex format (zeroized on drop).
    pub private_key_hex: Zeroizing<String>,
    /// Public key in hex format.
    pub public_key_hex: String,
    /// Sui address (`0x` + 64 hex chars).
    pub address: String,
}

impl<'a> Deriver<'a> {
    /// Create a new Sui deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive an address at the given account index.
    ///
    /// Uses SLIP-10 path: `m/44'/784'/{index}'/0'/0'`
    pub fn derive(&self, index: u32) -> Result<DerivedAddress, Error> {
        let derived_key = DerivedKey::derive_sui_path(self.wallet.seed(), index)?;
        let signing_key = derived_key.to_signing_key();
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32] = verifying_key.as_bytes();

        // Address = BLAKE2b-256(flag || pubkey)
        let mut buf = Vec::with_capacity(33);
        buf.push(ED25519_FLAG);
        buf.extend_from_slice(pubkey_bytes);
        let hash = blake2b_256(&buf);

        Ok(DerivedAddress {
            path: format!("m/44'/784'/{index}'/0'/0'"),
            private_key_hex: Zeroizing::new(hex::encode(signing_key.to_bytes())),
            public_key_hex: hex::encode(pubkey_bytes),
            address: format!("0x{}", hex::encode(hash)),
        })
    }
}

/// Compute BLAKE2b-256.
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    #[allow(clippy::expect_used)]
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 32];
    #[allow(clippy::expect_used)]
    hasher.finalize_variable(&mut out).expect("correct length");
    out
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
    fn derive_starts_with_0x() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert!(derived.address.starts_with("0x"));
    }

    #[test]
    fn derive_address_length() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.address.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path, "m/44'/784'/0'/0'/0'");
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
        assert_ne!(d.derive(0).unwrap().address, d.derive(1).unwrap().address);
    }

    #[test]
    fn address_correctness() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();

        // Manually compute: BLAKE2b-256(0x00 || pubkey)
        let pubkey_bytes = hex::decode(&derived.public_key_hex).unwrap();
        let mut buf = vec![ED25519_FLAG];
        buf.extend_from_slice(&pubkey_bytes);
        let expected = blake2b_256(&buf);
        assert_eq!(derived.address, format!("0x{}", hex::encode(expected)));
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
