//! Unified wallet type for multi-chain key derivation.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::Error;

/// A unified HD wallet that can derive keys for multiple cryptocurrencies.
///
/// This wallet holds a BIP39 mnemonic and derives a seed that can be used
/// to generate addresses for Bitcoin, Ethereum, and other coins following
/// BIP32/44/49/84 standards.
///
/// # Passphrase Support
///
/// The wallet supports an optional BIP39 passphrase (sometimes called "25th word").
/// This provides an extra layer of security - the same mnemonic with different
/// passphrases will produce completely different wallets.
#[derive(Debug)]
pub struct Wallet {
    /// BIP39 mnemonic phrase.
    mnemonic: Zeroizing<String>,
    /// Seed derived from mnemonic + passphrase.
    seed: Zeroizing<[u8; 64]>,
    /// Whether a passphrase was used.
    has_passphrase: bool,
}

impl Wallet {
    /// Generate a new wallet with a random mnemonic.
    ///
    /// # Arguments
    ///
    /// * `word_count` - Number of words (12, 15, 18, 21, or 24)
    /// * `passphrase` - Optional BIP39 passphrase for additional security
    ///
    /// # Errors
    ///
    /// Returns an error if the word count is invalid.
    ///
    /// # Note
    ///
    /// This function requires the `rand` feature to be enabled.
    #[cfg(feature = "rand")]
    pub fn generate(word_count: usize, passphrase: Option<&str>) -> Result<Self, Error> {
        if !matches!(word_count, 12 | 15 | 18 | 21 | 24) {
            return Err(Error::InvalidWordCount(word_count));
        }

        let mnemonic = Mnemonic::generate(word_count)?;
        Self::from_mnemonic(mnemonic.to_string().as_str(), passphrase)
    }

    /// Create a wallet from raw entropy bytes.
    ///
    /// This is useful in `no_std` environments where you provide your own entropy
    /// source instead of relying on the system RNG.
    ///
    /// # Arguments
    ///
    /// * `entropy` - Raw entropy bytes (16, 20, 24, 28, or 32 bytes for 12-24 words)
    /// * `passphrase` - Optional BIP39 passphrase for additional security
    ///
    /// # Errors
    ///
    /// Returns an error if the entropy length is invalid.
    pub fn from_entropy(entropy: &[u8], passphrase: Option<&str>) -> Result<Self, Error> {
        let mnemonic = Mnemonic::from_entropy(entropy)?;
        Self::from_mnemonic(mnemonic.to_string().as_str(), passphrase)
    }

    /// Create a wallet from an existing mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `phrase` - BIP39 mnemonic phrase
    /// * `passphrase` - Optional BIP39 passphrase
    ///
    /// # Errors
    ///
    /// Returns an error if the mnemonic is invalid.
    pub fn from_mnemonic(phrase: &str, passphrase: Option<&str>) -> Result<Self, Error> {
        let mnemonic: Mnemonic = phrase.parse()?;
        let passphrase_str = passphrase.unwrap_or("");
        let seed_bytes = mnemonic.to_seed(passphrase_str);

        Ok(Self {
            mnemonic: Zeroizing::new(mnemonic.to_string()),
            seed: Zeroizing::new(seed_bytes),
            has_passphrase: passphrase.is_some() && !passphrase_str.is_empty(),
        })
    }

    /// Get the mnemonic phrase.
    ///
    /// **Security Warning**: Handle this value carefully as it can
    /// reconstruct all derived keys.
    #[inline]
    #[must_use]
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Get the seed bytes for key derivation.
    ///
    /// This seed can be used by chain-specific derivers (Bitcoin, Ethereum, etc.)
    /// to generate addresses following their respective standards.
    #[inline]
    #[must_use]
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    /// Check if a passphrase was used to derive the seed.
    #[must_use]
    pub const fn has_passphrase(&self) -> bool {
        self.has_passphrase
    }

    /// Get the word count of the mnemonic.
    #[inline]
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.mnemonic.split_whitespace().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_12_words() {
        let wallet = Wallet::generate(12, None).unwrap();
        assert_eq!(wallet.word_count(), 12);
        assert!(!wallet.has_passphrase());
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_24_words() {
        let wallet = Wallet::generate(24, None).unwrap();
        assert_eq!(wallet.word_count(), 24);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_with_passphrase() {
        let wallet = Wallet::generate(12, Some("secret")).unwrap();
        assert!(wallet.has_passphrase());
    }

    #[test]
    fn test_invalid_entropy_length() {
        // 15 bytes is invalid (should be 16, 20, 24, 28, or 32)
        let result = Wallet::from_entropy(&[0u8; 15], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_entropy() {
        // 16 bytes = 12 words
        let entropy = [0u8; 16];
        let wallet = Wallet::from_entropy(&entropy, None).unwrap();
        assert_eq!(wallet.word_count(), 12);
    }

    #[test]
    fn test_from_mnemonic() {
        let wallet = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        assert_eq!(wallet.mnemonic(), TEST_MNEMONIC);
    }

    #[test]
    fn test_passphrase_changes_seed() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("password")).unwrap();

        // Same mnemonic with different passphrase should produce different seeds
        assert_ne!(wallet1.seed(), wallet2.seed());
    }

    #[test]
    fn test_deterministic_seed() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("test")).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("test")).unwrap();

        // Same mnemonic + passphrase should produce identical seeds
        assert_eq!(wallet1.seed(), wallet2.seed());
    }
}
