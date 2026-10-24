//! Mnemonic camouflage: `E' = E XOR K` with the result re-encoded as a
//! BIP-39 English mnemonic.
//!
//! Algorithm v1, byte-compatible with kobe v1.0.0–v4.0.0: `K` is
//! PBKDF2-HMAC-SHA256 of the password's raw UTF-8 bytes (salt
//! `kobe-mnemonic-camouflage-v1`, 600 000 iterations, `dkLen = |E|`).
//! XOR is self-inverse, so one routine serves both directions.

use alloc::string::String;

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::wallet::Wallet;

const SALT: &[u8] = b"kobe-mnemonic-camouflage-v1";
const ITERATIONS: u32 = 600_000;

/// `true` when `password` is already in Unicode Normalization Form C.
#[must_use]
pub fn is_nfc(password: &str) -> bool {
    unicode_normalization::is_nfc(password)
}

/// Disguise `wallet`'s mnemonic behind `password`. The password must be
/// non-empty and in NFC form so the same camouflaged phrase reproduces
/// under every input method.
///
/// # Errors
///
/// [`Error::InvalidValue`] when the password is empty or not NFC.
pub fn encrypt(wallet: &Wallet, password: &str) -> Result<Zeroizing<String>, Error> {
    if !is_nfc(password) {
        return Err(Error::InvalidValue(String::from(
            "password is not Unicode NFC; normalise it (or pick another) — \
             NFC and NFD forms encrypt to different mnemonics",
        )));
    }
    transform(wallet.entropy(), password)
}

/// Recover the original mnemonic from a camouflaged `wallet`. The
/// password is used byte-for-byte (no normalization) for compatibility
/// with mnemonics camouflaged by kobe ≤ v4.
///
/// # Errors
///
/// [`Error::InvalidValue`] when the password is empty.
pub fn decrypt(wallet: &Wallet, password: &str) -> Result<Zeroizing<String>, Error> {
    transform(wallet.entropy(), password)
}

fn transform(entropy: &[u8], password: &str) -> Result<Zeroizing<String>, Error> {
    if password.is_empty() {
        return Err(Error::InvalidValue(String::from(
            "password must not be empty",
        )));
    }
    let mut key = Zeroizing::new(alloc::vec![0u8; entropy.len()]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), SALT, ITERATIONS, &mut key);
    let mut xor = Zeroizing::new(entropy.to_vec());
    for (dst, kb) in xor.iter_mut().zip(key.iter()) {
        *dst ^= kb;
    }
    let mnemonic = Zeroizing::new(
        Mnemonic::from_entropy_in(Language::English, &xor)
            .map_err(|e| Error::Mnemonic(alloc::format!("{e}")))?,
    );
    // Words are at most 8 letters plus a separator: preallocated so the
    // phrase never reallocates and leaves an unzeroized copy behind.
    let mut out = Zeroizing::new(String::with_capacity(entropy.len() / 4 * 3 * 9));
    for (i, word) in mnemonic.words().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(word);
    }
    Ok(out)
}
