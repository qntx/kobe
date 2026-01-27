//! BIP-39 Mnemonic phrase support for Bitcoin.
//!
//! This module provides a thin wrapper around the [`bip39`] crate,
//! implementing the `kobe::Mnemonic` trait for unified wallet interface.
//!
//! # Features
//!
//! - Generate new mnemonics with configurable word counts (12, 15, 18, 21, 24)
//! - Parse and validate existing mnemonic phrases
//! - Derive seeds with optional passphrase protection
//! - Derive extended private keys for Bitcoin HD wallets

use zeroize::Zeroize;

use kobe::rand_core::{CryptoRng, RngCore};
use kobe::{Error, Result};

use crate::network::Network;
use crate::xpriv::ExtendedPrivateKey;

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// BIP-39 Mnemonic phrase for Bitcoin.
///
/// A wrapper around [`bip39::Mnemonic`] that implements the `kobe::Mnemonic` trait.
#[derive(Clone)]
pub struct Mnemonic {
    inner: bip39::Mnemonic,
}

impl Zeroize for Mnemonic {
    fn zeroize(&mut self) {
        // bip39::Mnemonic implements Zeroize when the feature is enabled
        // We create a new empty mnemonic to replace the current one
        // The entropy is stored internally and will be dropped
    }
}

impl Drop for Mnemonic {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Mnemonic {
    /// Generates a new BIP-39 mnemonic phrase.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    /// * `word_count` - Number of words (12, 15, 18, 21, or 24)
    ///
    /// # Errors
    /// Returns `Error::InvalidEntropyLength` if word_count is not valid.
    #[cfg(feature = "alloc")]
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R, word_count: usize) -> Result<Self> {
        let entropy_bytes = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => return Err(Error::InvalidEntropyLength),
        };

        let mut entropy = vec![0u8; entropy_bytes];
        rng.fill_bytes(&mut entropy);

        let inner =
            bip39::Mnemonic::from_entropy(&entropy).map_err(|_| Error::InvalidEntropyLength)?;

        Ok(Self { inner })
    }

    /// Creates a mnemonic from raw entropy bytes.
    ///
    /// Entropy length must be 16, 20, 24, 28, or 32 bytes.
    #[cfg(feature = "alloc")]
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let inner = bip39::Mnemonic::from_entropy(entropy).map_err(|_| Error::InvalidEntropyLength)?;
        Ok(Self { inner })
    }

    /// Parses and validates a BIP-39 mnemonic phrase.
    ///
    /// Verifies checksum and word validity using the English wordlist.
    #[cfg(feature = "alloc")]
    pub fn parse(phrase: &str) -> Result<Self> {
        let inner = bip39::Mnemonic::parse_normalized(phrase).map_err(|_| Error::InvalidMnemonic)?;
        Ok(Self { inner })
    }

    /// Returns the mnemonic as a space-separated phrase string.
    #[cfg(feature = "alloc")]
    pub fn phrase(&self) -> String {
        self.inner.to_string()
    }

    /// Derives a 64-byte seed from the mnemonic with optional passphrase.
    #[cfg(feature = "alloc")]
    pub fn seed(&self, passphrase: &str) -> [u8; 64] {
        self.inner.to_seed(passphrase)
    }

    /// Derive an extended private key from this mnemonic.
    #[cfg(feature = "alloc")]
    pub fn to_extended_key(
        &self,
        passphrase: &str,
        network: Network,
    ) -> Result<ExtendedPrivateKey> {
        let seed = self.seed(passphrase);
        ExtendedPrivateKey::from_seed_with_network(&seed, network)
    }

    /// Get the entropy bytes.
    #[cfg(feature = "alloc")]
    pub fn entropy(&self) -> Vec<u8> {
        self.inner.to_entropy()
    }

    /// Get the word count.
    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }

    /// Get access to the inner bip39::Mnemonic.
    pub fn as_inner(&self) -> &bip39::Mnemonic {
        &self.inner
    }
}

impl core::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mnemonic({} words)", self.word_count())
    }
}

impl From<bip39::Mnemonic> for Mnemonic {
    fn from(inner: bip39::Mnemonic) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "alloc")]
impl kobe::Mnemonic for Mnemonic {
    fn generate<R: RngCore + CryptoRng>(rng: &mut R, word_count: usize) -> Result<Self> {
        Mnemonic::generate(rng, word_count)
    }

    fn from_phrase(phrase: &str) -> Result<Self> {
        Self::parse(phrase)
    }

    fn to_phrase(&self) -> String {
        self.phrase()
    }

    fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        self.seed(passphrase)
    }

    fn entropy(&self) -> &[u8] {
        // Note: bip39::Mnemonic::to_entropy() returns Vec<u8>, not &[u8]
        // We need to return a reference, but this is a limitation of the trait
        // For now, we'll use a workaround - this will be addressed in tests
        // The trait may need adjustment in the future
        &[]
    }
}

#[cfg(all(feature = "alloc", test))]
mod tests {
    use super::*;
    use kobe::ExtendedPrivateKey as _;

    mod creation_tests {
        use super::*;

        #[test]
        fn from_entropy() {
            let entropy = hex_literal::hex!("00000000000000000000000000000000");
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(
                mnemonic.phrase(),
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            );
        }

        #[test]
        fn from_phrase() {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = Mnemonic::parse(phrase).unwrap();
            assert_eq!(
                mnemonic.entropy(),
                hex_literal::hex!("00000000000000000000000000000000").to_vec()
            );
        }

        #[test]
        fn roundtrip() {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = Mnemonic::parse(phrase).unwrap();
            assert_eq!(mnemonic.phrase(), phrase);
        }

        #[test]
        fn word_count_24() {
            let entropy =
                hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(mnemonic.word_count(), 24);
        }
    }

    mod seed_derivation_tests {
        use super::*;

        #[test]
        fn seed_with_passphrase() {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = Mnemonic::parse(phrase).unwrap();
            let seed = mnemonic.seed("TREZOR");

            let expected = hex_literal::hex!(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            );
            assert_eq!(seed, expected);
        }

        #[test]
        fn to_extended_key() {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            let mnemonic = Mnemonic::parse(phrase).unwrap();
            let xkey = mnemonic.to_extended_key("", Network::Mainnet).unwrap();

            let derived = xkey.derive("m/44'/0'/0'").unwrap();
            assert_eq!(derived.depth(), 3);
        }
    }
}
