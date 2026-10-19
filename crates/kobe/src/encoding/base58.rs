//! `Base58Check` encoding (btc-family, tron, xrp) and `WIF`.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(any(
    feature = "bitcoin",
    feature = "litecoin",
    feature = "dogecoin",
    feature = "bitcoin-cash"
))]
use zeroize::Zeroizing;

#[cfg(any(
    feature = "bitcoin",
    feature = "litecoin",
    feature = "dogecoin",
    feature = "bitcoin-cash"
))]
use crate::Error;
use crate::encoding::hash::double_sha256;

/// `Base58(payload ‖ checksum4)` over a selectable base58 alphabet.
#[cfg(any(
    feature = "bitcoin",
    feature = "litecoin",
    feature = "dogecoin",
    feature = "tron",
    feature = "xrpl",
))]
pub(crate) fn base58check_alphabet(payload: &[u8], alphabet: &bs58::Alphabet) -> String {
    let checksum = double_sha256(payload);
    let mut body = Vec::with_capacity(payload.len() + 4);
    body.extend_from_slice(payload);
    body.extend_from_slice(checksum.split_at(4).0);
    bs58::encode(body).with_alphabet(alphabet).into_string()
}

/// `Base58(payload ‖ checksum4)` over the Bitcoin alphabet.
#[cfg(any(
    feature = "bitcoin",
    feature = "litecoin",
    feature = "dogecoin",
    feature = "tron",
))]
pub(crate) fn base58check_encode(payload: &[u8]) -> String {
    base58check_alphabet(payload, bs58::Alphabet::BITCOIN)
}

/// Version byte + 20-byte payload (`P2PKH` / `P2SH` style, Tron `0x41`).
#[cfg(any(
    feature = "bitcoin",
    feature = "litecoin",
    feature = "dogecoin",
    feature = "tron",
))]
pub(crate) fn base58check_versioned(version: u8, payload: &[u8; 20]) -> String {
    let mut body = Vec::with_capacity(21);
    body.push(version);
    body.extend_from_slice(payload);
    base58check_encode(&body)
}

/// Compressed WIF: `Base58Check(version ‖ sk ‖ 0x01)`, encoded straight
/// into a zeroized buffer.
#[cfg(any(
    feature = "bitcoin",
    feature = "litecoin",
    feature = "dogecoin",
    feature = "bitcoin-cash"
))]
pub(crate) fn wif(version: u8, secret: &Zeroizing<[u8; 32]>) -> Result<Zeroizing<String>, Error> {
    let mut body = Zeroizing::new(Vec::with_capacity(38));
    body.push(version);
    body.extend_from_slice(secret.as_slice());
    body.push(0x01);
    let checksum = double_sha256(&body);
    body.extend_from_slice(checksum.split_at(4).0);
    let mut out = Zeroizing::new(String::new());
    bs58::encode(body.as_slice())
        .onto(&mut *out)
        .map_err(|e| Error::InvalidKey(alloc::format!("base58: {e}")))?;
    Ok(out)
}
