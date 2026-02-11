//! Standard (non-HD) Solana wallet implementation.
//!
//! A standard wallet uses a single randomly generated private key,
//! without mnemonic or HD derivation.
//!
#[cfg(feature = "rand")]
use rand_core::OsRng;

use alloc::string::String;
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::Error;

/// A standard Solana wallet with a single keypair.
///
/// This wallet type generates a random private key directly,
/// without using a mnemonic or HD derivation.
#[derive(Debug)]
pub struct StandardWallet {
    /// Ed25519 signing key.
    signing_key: SigningKey,
}

impl StandardWallet {
    /// Generate a new random wallet.
    ///
    /// Uses the operating system's cryptographically secure random number generator.
    #[cfg(feature = "rand")]
    #[must_use]
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a wallet from raw 32-byte secret key.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Create a wallet from a hex-encoded secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or key length is wrong.
    pub fn from_hex(hex_key: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_key).map_err(|_| Error::InvalidHex)?;

        if bytes.len() != 32 {
            return Err(Error::Derivation(alloc::format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&key_bytes))
    }

    /// Get the Solana address as Base58 encoded string.
    #[inline]
    #[must_use]
    pub fn address(&self) -> String {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        bs58::encode(verifying_key.as_bytes()).into_string()
    }

    /// Get the secret key as raw bytes (zeroized on drop).
    #[inline]
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.signing_key.as_bytes())
    }

    /// Get the secret key in hex format (zeroized on drop).
    #[inline]
    #[must_use]
    pub fn secret_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.signing_key.as_bytes()))
    }

    /// Get the public key in hex format.
    #[inline]
    #[must_use]
    pub fn pubkey_hex(&self) -> String {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        hex::encode(verifying_key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate() {
        let wallet = StandardWallet::generate();
        let address = wallet.address();

        // Solana addresses are 32-44 characters in Base58
        assert!(address.len() >= 32 && address.len() <= 44);
    }

    #[test]
    fn test_from_bytes() {
        let key = [1u8; 32];
        let wallet = StandardWallet::from_bytes(&key);
        let address = wallet.address();

        assert!(address.len() >= 32 && address.len() <= 44);
    }

    #[test]
    fn test_from_hex() {
        let hex_key = "0101010101010101010101010101010101010101010101010101010101010101";
        let wallet = StandardWallet::from_hex(hex_key).unwrap();
        let address = wallet.address();

        assert!(address.len() >= 32 && address.len() <= 44);
    }

    #[test]
    fn test_deterministic() {
        let key = [42u8; 32];
        let wallet1 = StandardWallet::from_bytes(&key);
        let wallet2 = StandardWallet::from_bytes(&key);

        assert_eq!(wallet1.address(), wallet2.address());
    }
}
