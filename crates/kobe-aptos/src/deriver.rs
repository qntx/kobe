//! Aptos address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};

pub use kobe_primitives::DerivedAccount;
use kobe_primitives::slip10::DerivedKey;
use kobe_primitives::{Derive, DeriveExt, Wallet};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::DeriveError;

/// Ed25519 single-signature scheme identifier used by Aptos.
const ED25519_SCHEME: u8 = 0x00;

/// Aptos address deriver from a unified wallet seed.
///
/// Derives Aptos addresses using SLIP-10 Ed25519 at path `m/44'/637'/{index}'/0'/0'`.
/// Address = `0x` + hex(SHA3-256(0x00 || pubkey)).
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Aptos deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive `count` accounts starting at `start` using the default Aptos path.
    ///
    /// Equivalent to [`DeriveExt::derive_many`] but available as an inherent method.
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails or `start + count` overflows.
    pub fn derive_many(&self, start: u32, count: u32) -> Result<Vec<DerivedAccount>, DeriveError> {
        <Self as DeriveExt>::derive_many(self, start, count)
    }

    /// Internal: derive at an arbitrary SLIP-10 path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let derived_key = DerivedKey::derive_path(self.wallet.seed(), path)?;
        let signing_key = derived_key.to_signing_key();
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32] = verifying_key.as_bytes();

        let mut buf = [0u8; 33];
        buf[0] = ED25519_SCHEME;
        buf[1..].copy_from_slice(pubkey_bytes);
        let hash = Sha3_256::digest(buf);

        Ok(DerivedAccount::new(
            String::from(path),
            Zeroizing::new(hex::encode(signing_key.to_bytes())),
            hex::encode(pubkey_bytes),
            format!("0x{}", hex::encode(hash)),
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(&format!("m/44'/637'/{index}'/0'/0'"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
}

#[cfg(test)]
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
        // 0x + 64 hex chars = 66 total
        assert_eq!(derived.address.len(), 66);
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path, "m/44'/637'/0'/0'/0'");
    }

    #[test]
    fn different_indices_differ() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        assert_ne!(d.derive(0).unwrap().address, d.derive(1).unwrap().address);
    }

    #[test]
    fn deterministic() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        assert_eq!(d.derive(0).unwrap().address, d.derive(0).unwrap().address);
    }

    #[test]
    fn kat_aptos_index0() {
        // Cross-verified with SLIP-10 Ed25519 m/44'/637'/0'/0'/0'
        // pubkey → SHA3-256(0x00 || pubkey)
        let wallet = test_wallet();
        let a = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(
            a.address,
            "0x00eb1449854fda728475c94f8078b7fd7670c1ed31deaf1e4f88e3bfe2cc2b6a"
        );
    }
}
