//! BIP-39 Mnemonic phrase support for Ethereum.
//!
//! Implements `kobe::Mnemonic` trait for unified wallet interface.
//!
//! # Multi-Language Support
//!
//! Supports multiple languages for mnemonic generation:
//! - English (default)
//! - Chinese Simplified (中文简体)
//! - Chinese Traditional (中文繁体)
//! - Japanese (日本語)
//! - Korean (한국어)
//! - Spanish, French, Italian

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use kobe::rand_core::{CryptoRng, RngCore};
use kobe::wordlist::bip39::Language;
use kobe::{Error, Result};

use crate::extended_key::EthExtendedPrivateKey;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Get wordlist for a specific language.
#[cfg(feature = "alloc")]
fn get_wordlist_for_language(language: Language) -> Vec<&'static str> {
    language.wordlist_str().lines().collect()
}

/// Number of PBKDF2 rounds for seed derivation.
const PBKDF2_ROUNDS: u32 = 2048;

/// BIP-39 Mnemonic phrase for Ethereum.
#[derive(Clone)]
pub struct EthMnemonic {
    /// The entropy bytes (16-32 bytes depending on word count)
    entropy: Vec<u8>,
    /// The language of the mnemonic
    language: Language,
}

impl Zeroize for EthMnemonic {
    fn zeroize(&mut self) {
        self.entropy.zeroize();
    }
}

impl Drop for EthMnemonic {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl EthMnemonic {
    /// Creates a mnemonic from raw entropy bytes (English by default).
    ///
    /// Entropy length must be 16, 20, 24, 28, or 32 bytes.
    #[cfg(feature = "alloc")]
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        Self::from_entropy_with_language(entropy, Language::English)
    }

    /// Create from existing entropy bytes with specific language.
    #[cfg(feature = "alloc")]
    pub fn from_entropy_with_language(entropy: &[u8], language: Language) -> Result<Self> {
        match entropy.len() {
            16 | 20 | 24 | 28 | 32 => Ok(Self {
                entropy: entropy.to_vec(),
                language,
            }),
            _ => Err(Error::InvalidEntropyLength),
        }
    }

    /// Generates a new BIP-39 mnemonic in the specified language.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    /// * `word_count` - Number of words (12, 15, 18, 21, or 24)
    /// * `language` - Target language for the mnemonic phrase
    #[cfg(feature = "alloc")]
    pub fn generate_with_language<R: RngCore + CryptoRng>(
        rng: &mut R,
        word_count: usize,
        language: Language,
    ) -> Result<Self> {
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

        Ok(Self { entropy, language })
    }

    /// Get the language of this mnemonic.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Parse mnemonic from phrase string (auto-detects language).
    #[cfg(feature = "alloc")]
    pub fn from_phrase_str(phrase: &str) -> Result<Self> {
        // Try each language to find a match
        for lang in Language::all() {
            if let Ok(mnemonic) = Self::from_phrase_str_with_language(phrase, *lang) {
                return Ok(mnemonic);
            }
        }
        Err(Error::InvalidMnemonic)
    }

    /// Parse mnemonic from phrase string with specific language.
    #[cfg(feature = "alloc")]
    pub fn from_phrase_str_with_language(phrase: &str, language: Language) -> Result<Self> {
        let words: Vec<&str> = phrase.split_whitespace().collect();

        let expected_bits = match words.len() {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => return Err(Error::InvalidMnemonic),
        };

        // Convert words to indices
        let wordlist = get_wordlist_for_language(language);
        let mut bits = Vec::with_capacity(words.len() * 11);
        for word in &words {
            let index = wordlist
                .iter()
                .position(|w| *w == *word)
                .ok_or(Error::InvalidWord)?;

            // Each word encodes 11 bits
            for i in (0..11).rev() {
                bits.push((index >> i) & 1 == 1);
            }
        }

        // Split into entropy and checksum
        let checksum_bits = expected_bits / 32;
        let entropy_bits = &bits[..expected_bits];
        let checksum = &bits[expected_bits..expected_bits + checksum_bits];

        // Convert entropy bits to bytes
        let mut entropy = vec![0u8; expected_bits / 8];
        for (i, bit) in entropy_bits.iter().enumerate() {
            if *bit {
                entropy[i / 8] |= 1 << (7 - (i % 8));
            }
        }

        // Verify checksum
        let hash = Sha256::digest(&entropy);
        for (i, &expected) in checksum.iter().enumerate() {
            let actual = (hash[i / 8] >> (7 - (i % 8))) & 1 == 1;
            if actual != expected {
                return Err(Error::InvalidChecksum);
            }
        }

        Ok(Self { entropy, language })
    }

    /// Convert mnemonic to phrase string.
    #[cfg(feature = "alloc")]
    pub fn to_phrase_string(&self) -> String {
        self.to_phrase_string_with_language(self.language)
    }

    /// Convert mnemonic to phrase string with specific language.
    #[cfg(feature = "alloc")]
    pub fn to_phrase_string_with_language(&self, language: Language) -> String {
        // Compute checksum
        let hash = Sha256::digest(&self.entropy);
        let checksum_bits = self.entropy.len() / 4; // CS = ENT / 32 bits

        // Combine entropy + checksum bits
        let total_bits = self.entropy.len() * 8 + checksum_bits;
        let mut bits = Vec::with_capacity(total_bits);

        // Add entropy bits
        for byte in &self.entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
            }
        }

        // Add checksum bits
        for i in 0..checksum_bits {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            bits.push((hash[byte_idx] >> bit_idx) & 1 == 1);
        }

        // Convert to words (11 bits each)
        let wordlist = get_wordlist_for_language(language);
        let mut words = Vec::with_capacity(bits.len() / 11);
        for chunk in bits.chunks(11) {
            let mut index = 0usize;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    index |= 1 << (10 - i);
                }
            }
            words.push(wordlist[index]);
        }

        words.join(" ")
    }

    /// Derive seed from mnemonic with optional passphrase.
    #[cfg(feature = "alloc")]
    pub fn to_seed_bytes(&self, passphrase: &str) -> [u8; 64] {
        let phrase = self.to_phrase_string();
        let salt = alloc::format!("mnemonic{}", passphrase);

        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(phrase.as_bytes(), salt.as_bytes(), PBKDF2_ROUNDS, &mut seed);

        seed
    }

    /// Derive an extended private key from this mnemonic.
    #[cfg(feature = "alloc")]
    pub fn to_extended_key(&self, passphrase: &str) -> Result<EthExtendedPrivateKey> {
        use kobe::ExtendedPrivateKey as _;
        let seed = self.to_seed_bytes(passphrase);
        EthExtendedPrivateKey::from_seed(&seed)
    }

    /// Get the entropy bytes.
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// Get the word count.
    pub fn word_count(&self) -> usize {
        (self.entropy.len() * 8 + self.entropy.len() / 4) / 11
    }
}

impl core::fmt::Debug for EthMnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mnemonic({} words)", self.word_count())
    }
}

#[cfg(feature = "alloc")]
impl kobe::Mnemonic for EthMnemonic {
    fn generate<R: RngCore + CryptoRng>(rng: &mut R, word_count: usize) -> Result<Self> {
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

        Ok(Self {
            entropy,
            language: Language::English,
        })
    }

    fn from_phrase(phrase: &str) -> Result<Self> {
        Self::from_phrase_str(phrase)
    }

    fn to_phrase(&self) -> String {
        self.to_phrase_string()
    }

    fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        self.to_seed_bytes(passphrase)
    }

    fn entropy(&self) -> &[u8] {
        &self.entropy
    }
}

#[cfg(all(feature = "alloc", test))]
mod tests {
    use super::*;
    use kobe::ExtendedPrivateKey as _;

    #[test]
    fn test_mnemonic_from_entropy() {
        // Test vector from BIP-39
        let entropy = hex_literal::hex!("00000000000000000000000000000000");
        let mnemonic = EthMnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.to_phrase_string();
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = EthMnemonic::from_phrase_str(phrase).unwrap();
        assert_eq!(
            mnemonic.entropy(),
            hex_literal::hex!("00000000000000000000000000000000")
        );
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = EthMnemonic::from_phrase_str(phrase).unwrap();
        let seed = mnemonic.to_seed_bytes("TREZOR");

        // Known test vector
        let expected = hex_literal::hex!(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        assert_eq!(seed, expected);
    }

    #[test]
    fn test_to_extended_key() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = EthMnemonic::from_phrase_str(phrase).unwrap();
        let xkey = mnemonic.to_extended_key("").unwrap();

        // Derive standard Ethereum path
        let derived = xkey.derive_path_str("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(derived.depth(), 5);

        // Check we can get an address
        let _addr = derived.address();
    }

    #[test]
    fn test_chinese_mnemonic() {
        // Test generating Chinese mnemonic from same entropy
        let entropy = hex_literal::hex!("00000000000000000000000000000000");
        let mnemonic =
            EthMnemonic::from_entropy_with_language(&entropy, Language::ChineseSimplified).unwrap();
        let phrase = mnemonic.to_phrase_string();

        // Chinese phrase for all-zero entropy
        assert!(phrase.contains("的")); // Common Chinese character
        assert_eq!(mnemonic.language(), Language::ChineseSimplified);

        // Same entropy should produce same seed regardless of language
        let english_mnemonic = EthMnemonic::from_entropy(&entropy).unwrap();
        let chinese_seed = mnemonic.to_seed_bytes("");
        let english_seed = english_mnemonic.to_seed_bytes("");

        // Note: Seeds are DIFFERENT because the phrase string is different
        // This is expected BIP-39 behavior
        assert_ne!(chinese_seed, english_seed);
    }

    #[test]
    fn test_language_detection() {
        // Test auto-detection of English phrase
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = EthMnemonic::from_phrase_str(phrase).unwrap();
        assert_eq!(mnemonic.language(), Language::English);
    }
}
