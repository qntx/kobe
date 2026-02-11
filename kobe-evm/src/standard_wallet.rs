//! Standard (non-HD) Ethereum wallet implementation.
//!
//! A standard wallet uses a single randomly generated private key,
//! without mnemonic or HD derivation.

#[cfg(feature = "alloc")]
use alloc::string::String;

use alloy_primitives::Address;
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use crate::Error;
use crate::address::{public_key_to_address, to_checksum_address};

/// A standard Ethereum wallet with a single private key.
///
/// This wallet type generates a random private key directly,
/// without using a mnemonic or HD derivation.
#[derive(Debug)]
pub struct StandardWallet {
    /// ECDSA signing key (secp256k1).
    private_key: SigningKey,
    /// Ethereum address derived from public key.
    address: Address,
}

impl StandardWallet {
    /// Generate a new standard wallet with a random private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    ///
    /// # Note
    ///
    /// This function requires the `rand` feature to be enabled.
    #[cfg(feature = "rand")]
    pub fn generate() -> Result<Self, Error> {
        use k256::elliptic_curve::rand_core::OsRng;
        let private_key = SigningKey::random(&mut OsRng);
        let address = Self::derive_address(&private_key);

        Ok(Self {
            private_key,
            address,
        })
    }

    /// Create a wallet from raw 32-byte secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is invalid.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let private_key = SigningKey::from_slice(bytes).map_err(|_| Error::InvalidPrivateKey)?;
        let address = Self::derive_address(&private_key);

        Ok(Self {
            private_key,
            address,
        })
    }

    /// Import a wallet from a hex-encoded secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or the secret key is invalid.
    pub fn from_hex(hex_str: &str) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|_| Error::InvalidHex)?;

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

    /// Get the secret key as raw bytes (zeroized on drop).
    #[inline]
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.private_key.to_bytes().into())
    }

    /// Get the secret key in hex format without 0x prefix (zeroized on drop).
    #[inline]
    #[must_use]
    pub fn secret_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.private_key.to_bytes()))
    }

    /// Get the public key in uncompressed hex format without 0x prefix.
    #[inline]
    #[must_use]
    pub fn pubkey_hex(&self) -> String {
        let public_key = self.private_key.verifying_key();
        let bytes = public_key.to_encoded_point(false);
        hex::encode(bytes.as_bytes())
    }

    /// Get the checksummed Ethereum address string.
    #[inline]
    #[must_use]
    pub fn address(&self) -> String {
        to_checksum_address(&self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate() {
        let wallet = StandardWallet::generate().unwrap();
        assert!(wallet.address().starts_with("0x"));
        assert_eq!(wallet.address().len(), 42);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_from_hex() {
        let wallet = StandardWallet::generate().unwrap();
        let hex = wallet.secret_hex();

        let imported = StandardWallet::from_hex(&hex).unwrap();
        assert_eq!(wallet.address(), imported.address());
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_from_hex_with_prefix() {
        use alloc::format;
        let wallet = StandardWallet::generate().unwrap();
        let hex = format!("0x{}", wallet.secret_hex().as_str());

        let imported = StandardWallet::from_hex(&hex).unwrap();
        assert_eq!(wallet.address(), imported.address());
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_from_bytes() {
        let wallet = StandardWallet::generate().unwrap();
        let bytes = wallet.secret_bytes();

        let imported = StandardWallet::from_bytes(&bytes).unwrap();
        assert_eq!(wallet.address(), imported.address());
    }
}
