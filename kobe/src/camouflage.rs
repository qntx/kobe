//! Mnemonic camouflage via entropy-layer XOR encryption.
//!
//! This module provides a way to disguise a real BIP-39 mnemonic as another
//! valid BIP-39 mnemonic using password-based encryption at the entropy layer.
//!
//! # How It Works
//!
//! 1. The real mnemonic is decoded into its raw entropy bytes.
//! 2. A 256-bit key is derived from the user's password via PBKDF2-HMAC-SHA256.
//! 3. The entropy is `XORed` with the derived key to produce new entropy.
//! 4. The new entropy is re-encoded as a valid BIP-39 mnemonic (with correct checksum).
//!
//! The resulting "camouflaged" mnemonic is indistinguishable from any other valid
//! BIP-39 mnemonic. Decryption uses the exact same process (XOR is its own inverse).
//!
//! # Security
//!
//! - The camouflaged mnemonic is a fully valid BIP-39 mnemonic.
//! - Without the password, it is computationally infeasible to recover the original.
//! - Security strength is bounded by the password entropy.
//! - PBKDF2 with 600,000 iterations provides strong resistance to brute-force attacks.

use alloc::string::String;

use bip39::{Language, Mnemonic};
use hmac::Hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Error;

/// PBKDF2 iteration count (OWASP 2023 recommendation for HMAC-SHA256).
const PBKDF2_ITERATIONS: u32 = 600_000;

/// Fixed salt for deterministic key derivation.
///
/// Using a fixed, domain-specific salt is acceptable here because:
/// - The goal is deterministic, stateless encryption (no stored state).
/// - PBKDF2's high iteration count provides brute-force resistance.
/// - Each unique password still produces a unique derived key.
const PBKDF2_SALT: &[u8] = b"kobe-mnemonic-camouflage-v1";

/// Maximum supported entropy length in bytes (256 bits for 24-word mnemonic).
const MAX_ENTROPY_LEN: usize = 32;

/// Encrypt a mnemonic phrase into a camouflaged mnemonic using the given password.
///
/// The output is a valid BIP-39 mnemonic that looks indistinguishable from any
/// other mnemonic. The original can only be recovered with the same password.
///
/// Supports 12, 15, 18, 21, and 24-word mnemonics.
///
/// # Arguments
///
/// * `phrase` - A valid BIP-39 mnemonic phrase
/// * `password` - Password used to derive the encryption key
///
/// # Errors
///
/// Returns an error if the mnemonic is invalid or if key derivation fails.
pub fn encrypt(phrase: &str, password: &str) -> Result<Zeroizing<String>, Error> {
    transform(Language::English, phrase, password)
}

/// Encrypt a mnemonic phrase in the specified language.
///
/// See [`encrypt`] for details.
pub fn encrypt_in(
    language: Language,
    phrase: &str,
    password: &str,
) -> Result<Zeroizing<String>, Error> {
    transform(language, phrase, password)
}

/// Decrypt a camouflaged mnemonic back to the original using the given password.
///
/// This is functionally identical to [`encrypt`] because XOR is its own inverse.
/// Provided as a separate function for API clarity.
///
/// # Arguments
///
/// * `camouflaged` - A camouflaged BIP-39 mnemonic phrase
/// * `password` - The same password used during encryption
///
/// # Errors
///
/// Returns an error if the mnemonic is invalid or if key derivation fails.
pub fn decrypt(camouflaged: &str, password: &str) -> Result<Zeroizing<String>, Error> {
    transform(Language::English, camouflaged, password)
}

/// Decrypt a camouflaged mnemonic in the specified language.
///
/// See [`decrypt`] for details.
pub fn decrypt_in(
    language: Language,
    camouflaged: &str,
    password: &str,
) -> Result<Zeroizing<String>, Error> {
    transform(language, camouflaged, password)
}

/// Core transformation: XOR the mnemonic's entropy with a password-derived key.
///
/// Since XOR is self-inverse, this single function handles both encryption
/// and decryption.
fn transform(language: Language, phrase: &str, password: &str) -> Result<Zeroizing<String>, Error> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }

    // Parse the mnemonic and extract raw entropy.
    let mnemonic = Mnemonic::parse_in(language, phrase)?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let entropy_len = entropy.len();

    // Derive a key from the password using PBKDF2-HMAC-SHA256.
    let key = derive_key(password, entropy_len)?;

    // XOR the entropy with the derived key.
    let mut new_entropy = Zeroizing::new([0u8; MAX_ENTROPY_LEN]);
    for i in 0..entropy_len {
        new_entropy[i] = entropy[i] ^ key[i];
    }

    // Re-encode as a valid BIP-39 mnemonic (checksum is recalculated automatically).
    let new_mnemonic = Mnemonic::from_entropy_in(language, &new_entropy[..entropy_len])?;
    Ok(Zeroizing::new(new_mnemonic.to_string()))
}

/// Derive a key from a password using PBKDF2-HMAC-SHA256.
///
/// Returns a [`Zeroizing`] buffer of exactly `len` bytes.
fn derive_key(password: &str, len: usize) -> Result<Zeroizing<[u8; MAX_ENTROPY_LEN]>, Error> {
    let mut key = Zeroizing::new([0u8; MAX_ENTROPY_LEN]);
    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        &mut key[..len],
    )
    .map_err(|_| Error::KeyDerivation)?;
    Ok(key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const TEST_15: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address";
    const TEST_18: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent";
    const TEST_21: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit";
    const TEST_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const PASSWORD: &str = "my-secret-password-2024";

    #[test]
    fn roundtrip_24_words() {
        let camouflaged = encrypt(TEST_24, PASSWORD).unwrap();

        // Camouflaged mnemonic must differ from original.
        assert_ne!(camouflaged.as_str(), TEST_24);

        // Camouflaged mnemonic must be a valid BIP-39 phrase.
        assert!(Mnemonic::parse_in(Language::English, camouflaged.as_str()).is_ok());

        // Decryption must recover the original.
        let recovered = decrypt(&camouflaged, PASSWORD).unwrap();
        assert_eq!(recovered.as_str(), TEST_24);
    }

    #[test]
    fn roundtrip_12_words() {
        let camouflaged = encrypt(TEST_12, PASSWORD).unwrap();
        assert_ne!(camouflaged.as_str(), TEST_12);

        let recovered = decrypt(&camouflaged, PASSWORD).unwrap();
        assert_eq!(recovered.as_str(), TEST_12);
    }

    #[test]
    fn roundtrip_15_words() {
        let camouflaged = encrypt(TEST_15, PASSWORD).unwrap();
        assert_ne!(camouflaged.as_str(), TEST_15);
        assert!(Mnemonic::parse_in(Language::English, camouflaged.as_str()).is_ok());

        let recovered = decrypt(&camouflaged, PASSWORD).unwrap();
        assert_eq!(recovered.as_str(), TEST_15);
    }

    #[test]
    fn roundtrip_18_words() {
        let camouflaged = encrypt(TEST_18, PASSWORD).unwrap();
        assert_ne!(camouflaged.as_str(), TEST_18);
        assert!(Mnemonic::parse_in(Language::English, camouflaged.as_str()).is_ok());

        let recovered = decrypt(&camouflaged, PASSWORD).unwrap();
        assert_eq!(recovered.as_str(), TEST_18);
    }

    #[test]
    fn roundtrip_21_words() {
        let camouflaged = encrypt(TEST_21, PASSWORD).unwrap();
        assert_ne!(camouflaged.as_str(), TEST_21);
        assert!(Mnemonic::parse_in(Language::English, camouflaged.as_str()).is_ok());

        let recovered = decrypt(&camouflaged, PASSWORD).unwrap();
        assert_eq!(recovered.as_str(), TEST_21);
    }

    #[test]
    fn different_passwords_produce_different_results() {
        let c1 = encrypt(TEST_24, "password-alpha").unwrap();
        let c2 = encrypt(TEST_24, "password-beta").unwrap();
        assert_ne!(c1.as_str(), c2.as_str());
    }

    #[test]
    fn wrong_password_does_not_recover() {
        let camouflaged = encrypt(TEST_24, PASSWORD).unwrap();
        let wrong = decrypt(&camouflaged, "wrong-password").unwrap();
        assert_ne!(wrong.as_str(), TEST_24);
    }

    #[test]
    fn deterministic_output() {
        let c1 = encrypt(TEST_24, PASSWORD).unwrap();
        let c2 = encrypt(TEST_24, PASSWORD).unwrap();
        assert_eq!(c1.as_str(), c2.as_str());
    }

    #[test]
    fn camouflaged_is_valid_mnemonic() {
        let camouflaged = encrypt(TEST_24, PASSWORD).unwrap();
        let wallet = crate::Wallet::from_mnemonic(&camouflaged, None);
        assert!(
            wallet.is_ok(),
            "camouflaged mnemonic must produce a valid wallet"
        );
    }

    #[test]
    fn empty_password_rejected() {
        let result = encrypt(TEST_24, "");
        assert!(result.is_err());
    }

    #[test]
    fn preserves_word_count() {
        for (phrase, expected_words) in [
            (TEST_12, 12),
            (TEST_15, 15),
            (TEST_18, 18),
            (TEST_21, 21),
            (TEST_24, 24),
        ] {
            let camouflaged = encrypt(phrase, PASSWORD).unwrap();
            let word_count = camouflaged.split_whitespace().count();
            assert_eq!(word_count, expected_words);
        }
    }
}
