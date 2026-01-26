//! BIP-39 Mnemonic phrase support.
//!
//! Implements `kobe::Mnemonic` trait for unified wallet interface.

use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use kobe::rand_core::{CryptoRng, RngCore};
use kobe::{Error, Result};

use crate::extended_key::BtcExtendedPrivateKey;
use crate::network::Network;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Lazy-initialized English wordlist from kobe.
#[cfg(feature = "alloc")]
fn get_wordlist() -> Vec<&'static str> {
    kobe::bip39::ENGLISH.lines().collect()
}

/// Number of PBKDF2 rounds for seed derivation.
const PBKDF2_ROUNDS: u32 = 2048;

/// BIP-39 Mnemonic phrase for Bitcoin.
#[derive(Clone)]
pub struct BtcMnemonic {
    /// The entropy bytes (16-32 bytes depending on word count)
    entropy: Vec<u8>,
}

impl Zeroize for BtcMnemonic {
    fn zeroize(&mut self) {
        self.entropy.zeroize();
    }
}

impl Drop for BtcMnemonic {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl BtcMnemonic {
    /// Generates a new BIP-39 mnemonic phrase.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    /// * `word_count` - Number of words (12, 15, 18, 21, or 24)
    ///
    /// # Example
    /// ```ignore
    /// let mnemonic = BtcMnemonic::generate(&mut rand::thread_rng(), 12)?;
    /// println!("{}", mnemonic.to_phrase_string());
    /// ```
    #[cfg(feature = "alloc")]
    pub fn generate<
        R: k256::elliptic_curve::rand_core::RngCore + k256::elliptic_curve::rand_core::CryptoRng,
    >(
        rng: &mut R,
        word_count: usize,
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

        Ok(Self { entropy })
    }

    /// Creates a mnemonic from raw entropy bytes.
    ///
    /// Entropy length must be 16, 20, 24, 28, or 32 bytes.
    #[cfg(feature = "alloc")]
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        match entropy.len() {
            16 | 20 | 24 | 28 | 32 => Ok(Self {
                entropy: entropy.to_vec(),
            }),
            _ => Err(Error::InvalidEntropyLength),
        }
    }

    /// Parses and validates a BIP-39 mnemonic phrase.
    ///
    /// Verifies checksum and extracts the underlying entropy.
    #[cfg(feature = "alloc")]
    pub fn from_phrase_str(phrase: &str) -> Result<Self> {
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
        let wordlist = get_wordlist();
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

        Ok(Self { entropy })
    }

    /// Convert mnemonic to phrase string.
    #[cfg(feature = "alloc")]
    pub fn to_phrase_string(&self) -> String {
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
        let wordlist = get_wordlist();
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
        let salt = format!("mnemonic{}", passphrase);

        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(phrase.as_bytes(), salt.as_bytes(), PBKDF2_ROUNDS, &mut seed);

        seed
    }

    /// Derive an extended private key from this mnemonic.
    #[cfg(feature = "alloc")]
    pub fn to_extended_key(
        &self,
        passphrase: &str,
        network: Network,
    ) -> Result<BtcExtendedPrivateKey> {
        let seed = self.to_seed_bytes(passphrase);
        BtcExtendedPrivateKey::from_seed_with_network(&seed, network)
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

impl core::fmt::Debug for BtcMnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mnemonic({} words)", self.word_count())
    }
}

#[cfg(feature = "alloc")]
impl kobe::Mnemonic for BtcMnemonic {
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

        Ok(Self { entropy })
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
    use kobe::Mnemonic as _;

    #[test]
    fn test_mnemonic_from_entropy() {
        // Test vector from BIP-39
        let entropy = hex_literal::hex!("00000000000000000000000000000000");
        let mnemonic = BtcMnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.to_phrase_string();
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = BtcMnemonic::from_phrase_str(phrase).unwrap();
        assert_eq!(
            mnemonic.entropy(),
            hex_literal::hex!("00000000000000000000000000000000")
        );
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = BtcMnemonic::from_phrase_str(phrase).unwrap();
        assert_eq!(mnemonic.to_phrase(), phrase);
    }

    #[test]
    fn test_mnemonic_to_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = BtcMnemonic::from_phrase_str(phrase).unwrap();
        let seed = mnemonic.to_seed_bytes("TREZOR");

        // Known test vector
        let expected = hex_literal::hex!(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        assert_eq!(seed, expected);
    }

    #[test]
    fn test_24_word_mnemonic() {
        let entropy =
            hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let mnemonic = BtcMnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.word_count(), 24);

        let phrase = mnemonic.to_phrase_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_to_extended_key() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = BtcMnemonic::from_phrase_str(phrase).unwrap();
        let xkey = mnemonic.to_extended_key("", Network::Mainnet).unwrap();

        // Derive BIP-44 Bitcoin account
        let derived = xkey.derive_path_str("m/44'/0'/0'").unwrap();
        assert_eq!(derived.depth(), 3);
    }
}
