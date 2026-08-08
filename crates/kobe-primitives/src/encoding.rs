//! Shared address-encoding primitives used by multiple chain crates.
//!
//! - [`hash160`] — Bitcoin / Cosmos / XRPL account-id style digests
//! - [`double_sha256`] — Bitcoin-style checksums
//! - [`base58check_encode`] — Bitcoin alphabet + 4-byte double-SHA-256 checksum
//!
//! Chain crates keep HRP, alphabet variants (XRPL), and script templates
//! locally; only the repeated hash / `Base58Check` steps live here.

use alloc::string::String;
use alloc::vec::Vec;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// `RIPEMD-160(SHA-256(data))` → 20 bytes.
///
/// Used by Bitcoin P2PKH/P2WPKH, Cosmos SDK bech32 payloads, and XRPL
/// classic account IDs.
#[must_use]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    Ripemd160::digest(sha).into()
}

/// `SHA-256(SHA-256(data))` → 32 bytes.
///
/// Used for Bitcoin `Base58Check` / WIF checksums and XRPL classic address
/// checksums (first 4 bytes).
#[must_use]
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// Bitcoin-alphabet `Base58Check`: `Base58(payload ‖ checksum4)`.
///
/// `checksum4` is the first 4 bytes of [`double_sha256`] over `payload`.
/// Callers supply the full pre-checksum body (e.g. `version ‖ hash160` for
/// P2PKH, or WIF's `version ‖ sk ‖ 0x01`).
#[must_use]
pub fn base58check_encode(payload: &[u8]) -> String {
    let checksum = double_sha256(payload);
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&checksum[..4]);
    bs58::encode(buf).into_string()
}

/// Convenience: version byte + 20-byte payload (`P2PKH` / `P2SH` style).
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "fixed-size 21-byte Base58Check body is sized by construction"
)]
pub fn base58check_versioned(version: u8, payload_20: &[u8; 20]) -> String {
    let mut body = [0u8; 21];
    body[0] = version;
    body[1..].copy_from_slice(payload_20);
    base58check_encode(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash160_empty_known() {
        // RIPEMD160(SHA256("")) — cross-checked with Python hashlib.
        let h = hash160(b"");
        assert_eq!(hex::encode(h), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    }

    #[test]
    fn base58check_p2pkh_mainnet_prefix() {
        // Arbitrary 20-byte payload; only checks encoding shape.
        let payload = [0x11u8; 20];
        let encoded = base58check_versioned(0x00, &payload);
        assert!(encoded.starts_with('1'));
    }

    #[test]
    fn double_sha256_deterministic() {
        let a = double_sha256(b"kobe");
        let b = double_sha256(b"kobe");
        assert_eq!(a, b);
        assert_ne!(a, double_sha256(b"other"));
    }
}
