//! Standard (non-HD) Ethereum wallet implementation.
//!
//! A standard wallet uses a single randomly generated private key.

use alloy_primitives::Address;
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::Error;
use crate::utils::{public_key_to_address, to_checksum_address};

// Re-export rand from k256 to avoid version conflicts
use k256::elliptic_curve::rand_core::OsRng;

/// A standard Ethereum wallet with a single private key.
///
/// This wallet type generates a random private key directly,
/// without using a mnemonic or HD derivation.
#[derive(Debug)]
pub struct StandardWallet {
    /// Private key.
    private_key: SigningKey,
    /// Ethereum address.
    address: Address,
}

impl StandardWallet {
    /// Generate a new standard wallet with a random private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<Self, Error> {
        let private_key = SigningKey::random(&mut OsRng);
        let address = Self::derive_address(&private_key);

        Ok(Self {
            private_key,
            address,
        })
    }

    /// Import a wallet from a private key hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid.
    pub fn from_private_key_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|_| Error::InvalidPrivateKey)?;

        let private_key = SigningKey::from_slice(&bytes).map_err(|_| Error::InvalidPrivateKey)?;
        let address = Self::derive_address(&private_key);

        Ok(Self {
            private_key,
            address,
        })
    }

    /// Derive address from private key.
    fn derive_address(private_key: &SigningKey) -> Address {
        let public_key = private_key.verifying_key();
        let public_key_bytes = public_key.to_encoded_point(false);
        public_key_to_address(public_key_bytes.as_bytes())
    }

    /// Get the private key in hex format (without 0x prefix).
    #[must_use]
    pub fn private_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.private_key.to_bytes()))
    }

    /// Get the public key in hex format (uncompressed, without 0x prefix).
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        let public_key = self.private_key.verifying_key();
        let bytes = public_key.to_encoded_point(false);
        hex::encode(bytes.as_bytes())
    }

    /// Get the Ethereum address.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Get the checksummed address string.
    #[must_use]
    pub fn address_string(&self) -> String {
        to_checksum_address(&self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let wallet = StandardWallet::generate().unwrap();
        assert!(wallet.address_string().starts_with("0x"));
        assert_eq!(wallet.address_string().len(), 42);
    }

    #[test]
    fn test_from_private_key() {
        let wallet = StandardWallet::generate().unwrap();
        let pk_hex = wallet.private_key_hex();

        let imported = StandardWallet::from_private_key_hex(&pk_hex).unwrap();
        assert_eq!(wallet.address_string(), imported.address_string());
    }

    #[test]
    fn test_from_private_key_with_prefix() {
        let wallet = StandardWallet::generate().unwrap();
        let pk_hex = format!("0x{}", wallet.private_key_hex().as_str());

        let imported = StandardWallet::from_private_key_hex(&pk_hex).unwrap();
        assert_eq!(wallet.address_string(), imported.address_string());
    }
}
