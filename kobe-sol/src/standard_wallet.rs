//! Standard (non-HD) Solana wallet implementation.
//!
//! A standard wallet uses a single randomly generated private key,
//! without mnemonic or HD derivation.

use alloc::string::String;
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::Error;

/// A standard Solana wallet with a single keypair.
///
/// This wallet type generates a random private key directly,
/// without using a mnemonic or HD derivation.
///
/// # Example
///
/// ```ignore
/// use kobe_sol::StandardWallet;
///
/// let wallet = StandardWallet::generate().unwrap();
/// println!("Address: {}", wallet.address_string());
/// println!("Private Key: {}", wallet.private_key_hex().as_str());
/// ```
#[derive(Debug)]
pub struct StandardWallet {
    /// Ed25519 signing key.
    signing_key: SigningKey,
}

impl StandardWallet {
    /// Generate a new random wallet.
    ///
    /// # Errors
    ///
    /// Returns an error if random generation fails.
    #[cfg(feature = "rand")]
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| Error::Derivation(alloc::format!("random generation failed: {e}")))?;
        let signing_key = SigningKey::from_bytes(&bytes);
        // Zeroize the temporary buffer
        bytes.iter_mut().for_each(|b| *b = 0);
        Ok(Self { signing_key })
    }

    /// Create a wallet from a raw 32-byte private key.
    #[must_use]
    pub fn from_private_key(private_key: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(private_key);
        Self { signing_key }
    }

    /// Create a wallet from a hex-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or key length is wrong.
    pub fn from_private_key_hex(hex_key: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex_key)
            .map_err(|e| Error::Derivation(alloc::format!("invalid hex: {e}")))?;

        if bytes.len() != 32 {
            return Err(Error::Derivation(alloc::format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(Self::from_private_key(&key_bytes))
    }

    /// Get the Solana address as Base58 encoded string.
    #[inline]
    #[must_use]
    pub fn address_string(&self) -> String {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        bs58::encode(verifying_key.as_bytes()).into_string()
    }

    /// Get the private key in hex format (zeroized on drop).
    #[inline]
    #[must_use]
    pub fn private_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.signing_key.as_bytes()))
    }

    /// Get the public key in hex format.
    #[inline]
    #[must_use]
    pub fn public_key_hex(&self) -> String {
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
        let wallet = StandardWallet::generate().unwrap();
        let address = wallet.address_string();

        // Solana addresses are 32-44 characters in Base58
        assert!(address.len() >= 32 && address.len() <= 44);
    }

    #[test]
    fn test_from_private_key() {
        let key = [1u8; 32];
        let wallet = StandardWallet::from_private_key(&key);
        let address = wallet.address_string();

        assert!(address.len() >= 32 && address.len() <= 44);
    }

    #[test]
    fn test_from_private_key_hex() {
        let hex_key = "0101010101010101010101010101010101010101010101010101010101010101";
        let wallet = StandardWallet::from_private_key_hex(hex_key).unwrap();
        let address = wallet.address_string();

        assert!(address.len() >= 32 && address.len() <= 44);
    }

    #[test]
    fn test_deterministic() {
        let key = [42u8; 32];
        let wallet1 = StandardWallet::from_private_key(&key);
        let wallet2 = StandardWallet::from_private_key(&key);

        assert_eq!(wallet1.address_string(), wallet2.address_string());
    }
}
