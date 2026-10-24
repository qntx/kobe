//! `SeedQR` payloads (`SeedSigner` `docs/seed_qr/README.md` spec): the
//! `standard` numeric digit stream and the `compact` raw-entropy bytes.
//! Encoding into a QR image happens in the CLI.

use alloc::string::String;
use alloc::vec::Vec;

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::wallet::Wallet;

fn word_count(wallet: &Wallet) -> Result<usize, Error> {
    let n = wallet.mnemonic().split_whitespace().count();
    match n {
        12 | 24 => Ok(n),
        _ => Err(Error::InvalidValue(alloc::format!(
            "SeedQR supports only 12 or 24 words, got {n}"
        ))),
    }
}

/// The standard `SeedQR` payload:
///
/// # Errors
///
/// [`Error::Mnemonic`] when the wallet is not 12 or 24 words, or
/// entropy cannot be re-expanded to a mnemonic. each word's BIP-39 English wordlist index
/// as a zero-padded 4-digit group, concatenated (48/96 digits).
pub fn standard(wallet: &Wallet) -> Result<Zeroizing<String>, Error> {
    word_count(wallet)?;
    // Rebuild the parsed mnemonic from the wallet's own entropy rather
    // than re-parsing the printed phrase.
    let mnemonic = Zeroizing::new(
        Mnemonic::from_entropy_in(Language::English, wallet.entropy())
            .map_err(|e| Error::Mnemonic(alloc::format!("{e}")))?,
    );
    // 24 words x 4 digits: preallocated so the buffer never reallocates
    // and leaves an unzeroized copy behind.
    let mut out = Zeroizing::new(String::with_capacity(96));
    for i in mnemonic.word_indices() {
        use core::fmt::Write as _;
        let _digit = write!(out, "{i:04}");
    }
    Ok(out)
}

/// The compact `SeedQR` payload:
///
/// # Errors
///
/// [`Error::Mnemonic`] when the wallet is not 12 or 24 words. the raw BIP-39 entropy bytes without the
/// checksum bits (16 or 32 bytes).
pub fn compact(wallet: &Wallet) -> Result<Zeroizing<Vec<u8>>, Error> {
    word_count(wallet)?;
    Ok(Zeroizing::new(wallet.entropy().to_vec()))
}
