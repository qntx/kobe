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

use alloc::string::{String, ToString};

use bip39::{Language, Mnemonic};
use hmac::{Hmac, KeyInit, Mac};
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
///
/// # Errors
///
/// Returns an error if the mnemonic is invalid, the password is empty,
/// or key derivation fails.
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
///
/// # Errors
///
/// Returns an error if the mnemonic is invalid, the password is empty,
/// or key derivation fails.
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

/// HMAC-SHA256 output size in bytes.
const HMAC_SHA256_LEN: usize = 32;

/// XOR `src` into `dest` (`dest[i] ^= src[i]`).
///
/// Handles the case where `dest` is shorter than `src` (last-block truncation).
#[inline(always)]
fn xor_buf(dest: &mut [u8], src: &[u8]) {
    dest.iter_mut().zip(src).for_each(|(d, s)| *d ^= s);
}

/// PBKDF2-HMAC-SHA256 (RFC 8018 §5.2).
///
/// Self-contained implementation verified against RFC 7914 §11 test vectors.
/// Structurally identical to the `RustCrypto` `pbkdf2` crate.
///
/// The `pbkdf2` crate is not used because its stable release (0.12) depends on
/// `digest 0.10`, which is incompatible with `hmac 0.13` / `sha2 0.11`
/// (`digest 0.11`). The `0.13` release is still in RC.
fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
) -> Result<(), Error> {
    let prf = Hmac::<Sha256>::new_from_slice(password).map_err(|_| Error::KeyDerivation)?;

    for (i, chunk) in output.chunks_mut(HMAC_SHA256_LEN).enumerate() {
        chunk.fill(0);

        // U_1 = PRF(password, salt || INT(i + 1))
        let mut mac = prf.clone();
        mac.update(salt);
        #[allow(clippy::cast_possible_truncation)]
        mac.update(&(i as u32 + 1).to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        xor_buf(chunk, &u);

        // U_2 .. U_c
        for _ in 1..iterations {
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes();
            xor_buf(chunk, &u);
        }
    }

    Ok(())
}

/// Derive a key from a password using [`pbkdf2_hmac_sha256`].
///
/// Returns a [`Zeroizing`] buffer of exactly `len` bytes.
fn derive_key(password: &str, len: usize) -> Result<Zeroizing<[u8; MAX_ENTROPY_LEN]>, Error> {
    let mut key = Zeroizing::new([0u8; MAX_ENTROPY_LEN]);
    pbkdf2_hmac_sha256(
        password.as_bytes(),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        &mut key[..len],
    )?;
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

    /// RFC 7914 §11 — PBKDF2-HMAC-SHA256("passwd", "salt", c=1, dkLen=64)
    ///
    /// Multi-block vector (64 bytes = 2 × HMAC-SHA256 blocks).
    #[test]
    fn pbkdf2_rfc7914_vector1() {
        #[rustfmt::skip]
        let expected: [u8; 64] = [
            0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
            0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
            0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
            0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
            0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45,
            0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
            0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
            0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
        ];
        let mut dk = [0u8; 64];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut dk).unwrap();
        assert_eq!(dk, expected);
    }

    /// RFC 7914 §11 — PBKDF2-HMAC-SHA256("Password", "`NaCl`", c=80000, dkLen=64)
    #[test]
    fn pbkdf2_rfc7914_vector2() {
        #[rustfmt::skip]
        let expected: [u8; 64] = [
            0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21,
            0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9,
            0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14,
            0xae, 0xff, 0x08, 0x87, 0x6b, 0x34, 0xab, 0x56,
            0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54,
            0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17,
            0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
            0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d,
        ];
        let mut dk = [0u8; 64];
        pbkdf2_hmac_sha256(b"Password", b"NaCl", 80_000, &mut dk).unwrap();
        assert_eq!(dk, expected);
    }

    /// Single-block output (32 bytes) — verifies first-block-only path.
    #[test]
    fn pbkdf2_rfc7914_vector1_single_block() {
        #[rustfmt::skip]
        let expected: [u8; 32] = [
            0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
            0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
            0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
            0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
        ];
        let mut dk = [0u8; 32];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut dk).unwrap();
        assert_eq!(dk, expected);
    }

    /// Truncated output (20 bytes) — verifies partial-block extraction.
    #[test]
    fn pbkdf2_truncated_output() {
        #[rustfmt::skip]
        let expected: [u8; 20] = [
            0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
            0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
            0xf9, 0x41, 0x85, 0x21,
        ];
        let mut dk = [0u8; 20];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut dk).unwrap();
        assert_eq!(dk, expected);
    }

    /// Empty output — degenerate case, must not panic.
    #[test]
    fn pbkdf2_empty_output() {
        let mut dk = [0u8; 0];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut dk).unwrap();
    }
}
