//! BIP-32 secp256k1 key derivation utilities.
//!
//! Provides a shared [`DerivedSecp256k1Key`] type used by all secp256k1-based
//! chain crates (EVM, Cosmos, Tron, Spark, Filecoin) to avoid duplicating
//! the `XPrv::derive_from_path` → `SigningKey` → public key pipeline.

use alloc::{format, string::String};

use bip32_crate::{DerivationPath, XPrv};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::DeriveError;

/// A secp256k1 key pair derived via BIP-32.
///
/// Wraps the derived signing key and provides convenient access to
/// private key bytes, compressed/uncompressed public key representations.
/// The signing key is zeroized on drop.
pub struct DerivedSecp256k1Key {
    /// BIP-32 extended private key (holds the signing key).
    xprv: XPrv,
}

impl DerivedSecp256k1Key {
    /// Derive a secp256k1 key pair from a 64-byte seed at the given BIP-32 path.
    ///
    /// # Arguments
    ///
    /// * `seed` - 64-byte BIP-39 seed
    /// * `path` - BIP-32 derivation path (e.g. `m/44'/60'/0'/0/0`)
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or derivation fails.
    pub fn derive(seed: &[u8; 64], path: &str) -> Result<Self, DeriveError> {
        let dp: DerivationPath = path
            .parse()
            .map_err(|e| DeriveError::Bip32Derivation(format!("invalid path: {e}")))?;
        let xprv = XPrv::derive_from_path(seed, &dp)
            .map_err(|e| DeriveError::Bip32Derivation(format!("derivation failed: {e}")))?;
        Ok(Self { xprv })
    }

    /// Get the raw 32-byte private key, zeroized on drop.
    #[must_use]
    pub fn private_key_bytes(&self) -> Zeroizing<[u8; 32]> {
        let sk: &SigningKey = self.xprv.private_key();
        let bytes = sk.to_bytes();
        Zeroizing::new(bytes.into())
    }

    /// Get the private key as a hex string, zeroized on drop.
    #[must_use]
    pub fn private_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(*self.private_key_bytes()))
    }

    /// Get the 33-byte compressed public key.
    #[must_use]
    pub fn compressed_pubkey(&self) -> [u8; 33] {
        let sk: &SigningKey = self.xprv.private_key();
        let point = sk.verifying_key().to_encoded_point(true);
        let bytes = point.as_bytes();
        let mut out = [0u8; 33];
        out.copy_from_slice(bytes);
        out
    }

    /// Get the compressed public key as a hex string.
    #[must_use]
    pub fn compressed_pubkey_hex(&self) -> String {
        hex::encode(self.compressed_pubkey())
    }

    /// Get the 65-byte uncompressed public key (04 || x || y).
    #[must_use]
    pub fn uncompressed_pubkey(&self) -> [u8; 65] {
        let sk: &SigningKey = self.xprv.private_key();
        let point = sk.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        let mut out = [0u8; 65];
        out.copy_from_slice(bytes);
        out
    }

    /// Get the uncompressed public key as a hex string.
    #[must_use]
    pub fn uncompressed_pubkey_hex(&self) -> String {
        hex::encode(self.uncompressed_pubkey())
    }
}

impl core::fmt::Debug for DerivedSecp256k1Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedSecp256k1Key")
            .field("compressed_pubkey", &self.compressed_pubkey_hex())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-39 "abandon...about" seed (Python cross-verified)
    fn kat_seed() -> [u8; 64] {
        let wallet = crate::Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            None,
        ).unwrap();
        let mut out = [0u8; 64];
        out.copy_from_slice(wallet.seed());
        out
    }

    #[test]
    fn kat_ethereum_path() {
        let seed = kat_seed();
        let key = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(
            key.private_key_hex().as_str(),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
        assert_eq!(
            key.compressed_pubkey_hex(),
            "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"
        );
    }

    #[test]
    fn uncompressed_pubkey_starts_with_04() {
        let seed = kat_seed();
        let key = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(key.uncompressed_pubkey()[0], 0x04);
        assert_eq!(key.uncompressed_pubkey().len(), 65);
    }

    #[test]
    fn different_paths_produce_different_keys() {
        let seed = kat_seed();
        let k0 = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        let k1 = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/1").unwrap();
        assert_ne!(*k0.private_key_bytes(), *k1.private_key_bytes());
    }

    #[test]
    fn deterministic() {
        let seed = kat_seed();
        let a = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        let b = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(*a.private_key_bytes(), *b.private_key_bytes());
    }

    #[test]
    fn invalid_path_rejected() {
        let seed = kat_seed();
        assert!(DerivedSecp256k1Key::derive(&seed, "bad").is_err());
    }
}
