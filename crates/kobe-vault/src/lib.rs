//! Versioned authenticated-envelope encryption and key derivation.
//!
//! # Envelope v1
//!
//! AES-256-GCM with a 96-bit nonce drawn from the caller's RNG and a
//! 128-bit tag. The associated data is `[0x01] || UTF-8(context)`, binding
//! both the envelope version and the application-chosen context into the
//! ciphertext. Sealed bytes are `[0x01] || nonce(12) || ciphertext || tag(16)`
//! with a minimum length of 29 bytes (an empty plaintext is allowed).
//!
//! # Key derivation
//!
//! - [`password_key`] — PBKDF2-HMAC-SHA256 over `UTF-8(NFKC(password))`,
//!   32-byte output.
//! - [`prf_key`] — HKDF-SHA256 (RFC 5869) over a 32-byte PRF output (for
//!   example a `WebAuthn` `prf` extension result).
//! - [`passkey_wallet`] — turns a 32-byte PRF output into a 12-word
//!   [`Wallet`] via `Wallet::from_entropy(prf[0..16])`.
//!
//! # Error codes
//!
//! All failures surface as [`kobe_core::Error`], sharing the machine-readable
//! `code` vocabulary with the TypeScript `@qntx/wallet/vault` implementation:
//! `input` for caller-supplied validation failures, `version` for a sealed
//! blob with an unsupported version byte, `decrypt` for AEAD open failure.
//! Error messages never contain key, plaintext, or password material.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub use kobe_core::{Error, Wallet};

/// Envelope format version byte. Written as `sealed[0]` and bound into the
/// AAD, so a blob cannot be re-versioned without detection.
pub const VERSION: u8 = 1;

/// Recommended PBKDF2-HMAC-SHA256 iteration count for [`password_key`].
pub const PASSWORD_ITERATIONS: u32 = 600_000;

/// Minimum sealed length: version(1) + nonce(12) + tag(16) with an empty
/// ciphertext.
const SEALED_MIN_LEN: usize = 29;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MAX_PASSWORD_ITERATIONS: u32 = 10_000_000;

/// Seal `plaintext` under `key` with the given `context` (envelope v1).
///
/// `context` must be a non-empty UTF-8 string chosen by the application;
/// it is bound into the ciphertext as associated data, so `open` with a
/// different context fails.
///
/// # Errors
///
/// [`Error::Input`] if `key` is not 32 bytes or `context` is empty.
/// [`Error::Crypto`] if the AEAD primitive fails.
pub fn seal<R: rand_core::CryptoRng + ?Sized>(
    key: &[u8],
    plaintext: &[u8],
    context: &str,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    check_key(key)?;
    check_context(context)?;

    let mut nonce = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(&mut nonce[..]);

    let nonce = Nonce::<U12>::from(*nonce);
    let aad = aad(context);
    let ct = cipher(key)?
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto(String::from("vault: aes-gcm seal failed")))?;

    let mut sealed = Vec::with_capacity(SEALED_MIN_LEN + plaintext.len());
    sealed.push(VERSION);
    sealed.extend_from_slice(&nonce[..]);
    sealed.extend_from_slice(&ct);
    Ok(sealed)
}

/// Open a sealed envelope v1 blob under `key` with the given `context`.
///
/// Checks, in order: key length, non-empty context, minimum length,
/// version byte, then AEAD open.
///
/// # Errors
///
/// [`Error::Input`] if `key` is not 32 bytes, `context` is empty, or
/// `sealed` is shorter than 29 bytes. [`Error::UnsupportedVersion`] if the
/// version byte is not [`VERSION`]. [`Error::Decrypt`] if AEAD open fails
/// (wrong key, tampered data, or mismatched context).
pub fn open(key: &[u8], sealed: &[u8], context: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    check_key(key)?;
    check_context(context)?;
    if sealed.len() < SEALED_MIN_LEN {
        return Err(Error::Input(String::from("vault: sealed data too short")));
    }
    let version = sealed.first().copied().unwrap_or(0);
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }

    let aad = aad(context);
    let payload = sealed.get(NONCE_LEN + 1..).unwrap_or(&[]);
    let nonce: &Nonce<U12> = sealed
        .get(1..NONCE_LEN + 1)
        .unwrap_or(&[])
        .try_into()
        .map_err(|_| Error::Decrypt)?;
    let pt = cipher(key)?
        .decrypt(
            nonce,
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(Zeroizing::new(pt))
}

/// Derive a 32-byte key from `password` via PBKDF2-HMAC-SHA256 over
/// `UTF-8(NFKC(password))`.
///
/// # Errors
///
/// [`Error::Input`] if the password is empty after NFKC normalization,
/// `salt` is shorter than 16 bytes, or `iterations` is outside
/// `1..=10_000_000`.
pub fn password_key(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let normalized = Zeroizing::new(password.nfkc().collect::<String>());
    if normalized.is_empty() {
        return Err(Error::Input(String::from(
            "vault: password must not be empty",
        )));
    }
    if salt.len() < 16 {
        return Err(Error::Input(alloc::format!(
            "vault: salt must be at least 16 bytes, got {}",
            salt.len()
        )));
    }
    if iterations == 0 || iterations > MAX_PASSWORD_ITERATIONS {
        return Err(Error::Input(alloc::format!(
            "vault: iterations must be 1 to {MAX_PASSWORD_ITERATIONS}, got {iterations}"
        )));
    }

    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(normalized.as_bytes(), salt, iterations, &mut out[..]);
    Ok(out)
}

/// Derive a 32-byte key from a PRF output (e.g. `WebAuthn` `prf`) via
/// HKDF-SHA256 (RFC 5869) with an empty salt and `info = UTF-8(info)`.
///
/// # Errors
///
/// [`Error::Input`] if `prf_output` is not exactly 32 bytes or `info` is
/// empty.
pub fn prf_key(prf_output: &[u8], info: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    if prf_output.len() != KEY_LEN {
        return Err(Error::Input(alloc::format!(
            "vault: PRF output must be 32 bytes, got {}",
            prf_output.len()
        )));
    }
    if info.is_empty() {
        return Err(Error::Input(String::from("vault: info must not be empty")));
    }

    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, prf_output);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), &mut out[..])
        .map_err(|_| Error::Crypto(String::from("vault: hkdf expand failed")))?;
    Ok(out)
}

/// Build a 12-word [`Wallet`] from a 32-byte PRF output:
/// `Wallet::from_entropy(prf[0..16])` with no passphrase.
///
/// The PRF input is chosen by the application; kobe only consumes the
/// 32-byte output.
///
/// # Errors
///
/// [`Error::Input`] if `prf_output` is not exactly 32 bytes.
pub fn passkey_wallet(prf_output: &[u8]) -> Result<Wallet, Error> {
    if prf_output.len() != KEY_LEN {
        return Err(Error::Input(alloc::format!(
            "vault: PRF output must be 32 bytes, got {}",
            prf_output.len()
        )));
    }
    let entropy = prf_output.get(..16).unwrap_or(&[]);
    Wallet::from_entropy(entropy, None)
}

fn check_key(key: &[u8]) -> Result<(), Error> {
    if key.len() != KEY_LEN {
        return Err(Error::Input(alloc::format!(
            "vault: key must be 32 bytes, got {}",
            key.len()
        )));
    }
    Ok(())
}

fn check_context(context: &str) -> Result<(), Error> {
    if context.is_empty() {
        return Err(Error::Input(String::from(
            "vault: context must not be empty",
        )));
    }
    Ok(())
}

/// AAD = `[VERSION] || UTF-8(context)` — the version byte is bound in.
fn aad(context: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + context.len());
    aad.push(VERSION);
    aad.extend_from_slice(context.as_bytes());
    aad
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm, Error> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Input(String::from("vault: key must be 32 bytes")))
}
