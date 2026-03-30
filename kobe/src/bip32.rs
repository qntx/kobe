//! BIP-32 secp256k1 key derivation utilities.
//!
//! Provides a shared [`DerivedSecp256k1Key`] type used by all secp256k1-based
//! chain crates (EVM, Cosmos, Tron, Spark, Filecoin) to avoid duplicating
//! the `XPrv::derive_from_path` → `SigningKey` → public key pipeline.

use alloc::{format, string::String};

use bip32_crate::{DerivationPath, XPrv};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::Error;

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
    pub fn derive(seed: &[u8; 64], path: &str) -> Result<Self, Error> {
        let dp: DerivationPath = path
            .parse()
            .map_err(|e| Error::Bip32Derivation(format!("invalid path: {e}")))?;
        let xprv = XPrv::derive_from_path(seed, &dp)
            .map_err(|e| Error::Bip32Derivation(format!("derivation failed: {e}")))?;
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 64] {
        let mut seed = [0u8; 64];
        seed[0] = 1;
        seed
    }

    #[test]
    fn derive_ethereum_path() {
        let seed = test_seed();
        let key = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(key.compressed_pubkey().len(), 33);
        assert_eq!(key.uncompressed_pubkey().len(), 65);
        assert_eq!(key.uncompressed_pubkey()[0], 0x04);
    }

    #[test]
    fn derive_cosmos_path() {
        let seed = test_seed();
        let key = DerivedSecp256k1Key::derive(&seed, "m/44'/118'/0'/0/0").unwrap();
        let compressed = key.compressed_pubkey();
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
    }

    #[test]
    fn private_key_is_32_bytes() {
        let seed = test_seed();
        let key = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(key.private_key_bytes().len(), 32);
    }

    #[test]
    fn hex_representations_match() {
        let seed = test_seed();
        let key = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(key.private_key_hex().len(), 64);
        assert_eq!(key.compressed_pubkey_hex().len(), 66);
        assert_eq!(key.uncompressed_pubkey_hex().len(), 130);
    }

    #[test]
    fn different_paths_produce_different_keys() {
        let seed = test_seed();
        let k0 = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        let k1 = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/1").unwrap();
        assert_ne!(*k0.private_key_bytes(), *k1.private_key_bytes());
    }

    #[test]
    fn invalid_path_rejected() {
        let seed = test_seed();
        assert!(DerivedSecp256k1Key::derive(&seed, "bad").is_err());
    }

    #[test]
    fn deterministic() {
        let seed = test_seed();
        let a = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        let b = DerivedSecp256k1Key::derive(&seed, "m/44'/60'/0'/0/0").unwrap();
        assert_eq!(*a.private_key_bytes(), *b.private_key_bytes());
    }
}
