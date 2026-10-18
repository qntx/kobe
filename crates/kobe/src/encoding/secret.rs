//! Formatting of secret key material into `Zeroizing` buffers, so no
//! plain `String`/`Vec` copy of secret-derived bytes ever exists.

use alloc::string::String;

use zeroize::Zeroizing;

#[cfg(any(feature = "sol", feature = "near"))]
use crate::Error;

/// Hex digit for the low nibble of a byte.
#[cfg(any(
    feature = "aptos",
    feature = "casper",
    feature = "cosmos",
    feature = "evm",
    feature = "fil",
    feature = "kaspa",
    feature = "spark",
    feature = "ton",
    feature = "tron",
    feature = "xrp",
))]
fn hex_digit(nibble: u8) -> char {
    char::from(if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    })
}

/// Append `data` as lowercase hex to `out`.
#[cfg(any(
    feature = "aptos",
    feature = "casper",
    feature = "cosmos",
    feature = "evm",
    feature = "fil",
    feature = "kaspa",
    feature = "spark",
    feature = "ton",
    feature = "tron",
    feature = "xrp",
))]
pub(crate) fn push_hex(out: &mut String, data: &[u8]) {
    out.reserve(data.len() * 2);
    for &b in data {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0f));
    }
}

/// `data` as a zeroized lowercase-hex string.
#[cfg(any(
    feature = "casper",
    feature = "cosmos",
    feature = "fil",
    feature = "kaspa",
    feature = "spark",
    feature = "ton",
    feature = "tron",
    feature = "xrp",
))]
pub(crate) fn hex_secret(data: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(data.len() * 2));
    push_hex(&mut out, data);
    out
}

/// `prefix ‖ hex(data)` in a zeroized string (`0x…`, `ed25519-priv-0x…`).
#[cfg(any(feature = "aptos", feature = "evm"))]
pub(crate) fn hex_secret_prefixed(prefix: &str, data: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(prefix.len() + data.len() * 2));
    out.push_str(prefix);
    push_hex(&mut out, data);
    out
}

/// Append `data` base58-encoded (Bitcoin alphabet) to `out`.
#[cfg(any(feature = "sol", feature = "near"))]
pub(crate) fn push_base58(out: &mut String, data: &[u8]) -> Result<(), Error> {
    bs58::encode(data)
        .onto(out)
        .map(|_| ())
        .map_err(|e| Error::InvalidKey(alloc::format!("base58: {e}")))
}

/// `data` base58-encoded into a zeroized string.
#[cfg(feature = "sol")]
pub(crate) fn base58_secret(data: &[u8]) -> Result<Zeroizing<String>, Error> {
    let mut out = Zeroizing::new(String::new());
    push_base58(&mut out, data)?;
    Ok(out)
}

/// `prefix ‖ base58(data)` in a zeroized string (`ed25519:…`).
#[cfg(feature = "near")]
pub(crate) fn base58_secret_prefixed(
    prefix: &str,
    data: &[u8],
) -> Result<Zeroizing<String>, Error> {
    let mut out = Zeroizing::new(String::with_capacity(prefix.len() + data.len() * 2));
    out.push_str(prefix);
    push_base58(&mut out, data)?;
    Ok(out)
}

/// Append `data` base64-encoded (standard alphabet, with padding) to `out`.
#[cfg(feature = "fil")]
pub(crate) fn push_base64(out: &mut String, data: &[u8]) {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode_string(data, out);
}
