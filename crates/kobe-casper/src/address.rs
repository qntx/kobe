//! Casper `PublicKey` tagging and `AccountHash` encoding.
//!
//! Encoding matches `casper-types` (`casper-node` `types` crate):
//!
//! - **Tagged public key** (serialization / display hex): tag byte + raw key.
//! - **`AccountHash`** preimage: `algorithm_name || 0x00 || raw_key` (no tag).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use blake2::{Blake2b256, Digest};
use kobe_primitives::DeriveError;

/// Prefix applied to the hex-encoded `AccountHash` for display.
pub const ACCOUNT_HASH_PREFIX: &str = "account-hash-";

/// Casper serialization tag for Ed25519 public keys (`PublicKey::Ed25519`).
pub const ED25519_TAG: u8 = 0x01;

/// Casper serialization tag for secp256k1 public keys (`PublicKey::Secp256k1`).
pub const SECP256K1_TAG: u8 = 0x02;

/// Lowercase algorithm name used in the `AccountHash` preimage (Ed25519).
const ED25519_NAME: &[u8] = b"ed25519";

/// Lowercase algorithm name used in the `AccountHash` preimage (secp256k1).
const SECP256K1_NAME: &[u8] = b"secp256k1";

/// Format a 32-byte `AccountHash` digest as `account-hash-` + lowercase hex.
#[inline]
#[must_use]
pub fn format_account_hash(digest: &[u8; 32]) -> String {
    format!("{ACCOUNT_HASH_PREFIX}{}", hex::encode(digest))
}

/// Tagged public-key hex (no `0x` prefix): `01 ‖ ed25519` or `02 ‖ secp`.
///
/// `raw_key` must be the 32-byte Ed25519 key or 33-byte compressed secp256k1
/// key (without the Casper algorithm tag).
#[inline]
#[must_use]
pub fn tagged_public_key_hex(tag: u8, raw_key: &[u8]) -> String {
    let mut buf = Vec::with_capacity(1 + raw_key.len());
    buf.push(tag);
    buf.extend_from_slice(raw_key);
    hex::encode(buf)
}

/// Compute the Casper `AccountHash` for an Ed25519 public key.
///
/// Preimage: `b"ed25519" || 0x00 || pubkey` (32-byte raw key).
///
/// # Errors
///
/// Returns [`DeriveError::Crypto`] if `BLAKE2b` initialization or finalization
/// fails (should not occur for a fixed 32-byte output size).
pub fn account_hash_ed25519(pubkey: &[u8; 32]) -> Result<[u8; 32], DeriveError> {
    account_hash_from_parts(ED25519_NAME, pubkey)
}

/// Compute the Casper `AccountHash` for a compressed secp256k1 public key.
///
/// Preimage: `b"secp256k1" || 0x00 || compressed_pubkey` (33-byte `SEC1`).
///
/// # Errors
///
/// Returns [`DeriveError::Crypto`] if `BLAKE2b` initialization or finalization
/// fails.
pub fn account_hash_secp256k1(compressed_pubkey: &[u8; 33]) -> Result<[u8; 32], DeriveError> {
    account_hash_from_parts(SECP256K1_NAME, compressed_pubkey)
}

/// Shared `AccountHash` construction: `name || 0x00 || raw_key` → `BLAKE2b`-256.
fn account_hash_from_parts(algorithm_name: &[u8], raw_key: &[u8]) -> Result<[u8; 32], DeriveError> {
    let mut preimage = Vec::with_capacity(algorithm_name.len() + 1 + raw_key.len());
    preimage.extend_from_slice(algorithm_name);
    preimage.push(0);
    preimage.extend_from_slice(raw_key);
    blake2b_256(&preimage)
}

/// `BLAKE2b`-256 (empty key), matching Casper's `crypto::blake2b`.
fn blake2b_256(data: &[u8]) -> Result<[u8; 32], DeriveError> {
    Ok(Blake2b256::digest(data).into())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "unit tests panic on assertion failure"
)]
mod tests {
    use super::*;

    /// Independent stdlib-equivalent vectors: preimage is `name||0x00||key`,
    /// digest is `BLAKE2b`-256. Cross-checked with Python `hashlib.blake2b`.
    #[test]
    fn kat_account_hash_ed25519_fixed_key() {
        let pk = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let pk: [u8; 32] = pk.try_into().unwrap();
        let digest = account_hash_ed25519(&pk).unwrap();
        assert_eq!(
            hex::encode(digest),
            "5b1c945c6e0923bf4f8da320444804791eb60d70983c7c5756d8ef236c1fdece"
        );
        assert_eq!(
            format_account_hash(&digest),
            "account-hash-5b1c945c6e0923bf4f8da320444804791eb60d70983c7c5756d8ef236c1fdece"
        );
        assert_eq!(
            tagged_public_key_hex(ED25519_TAG, &pk),
            "010123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    /// secp256k1 generator point (compressed) — independent `BLAKE2b` KAT.
    #[test]
    fn kat_account_hash_secp256k1_generator() {
        let pk = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        let pk: [u8; 33] = pk.try_into().unwrap();
        let digest = account_hash_secp256k1(&pk).unwrap();
        assert_eq!(
            hex::encode(digest),
            "86937931937ee0281e50806b94f8d4993e8869b0689dfa0a21d2946ab677183c"
        );
        assert_eq!(
            tagged_public_key_hex(SECP256K1_TAG, &pk),
            "020279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    /// Preimage must include the null separator; wrong layout must not match.
    #[test]
    fn preimage_includes_null_separator() {
        let pk = [0xab_u8; 32];
        let good = account_hash_ed25519(&pk).unwrap();
        // Tag-only layout (incorrect for AccountHash) must differ.
        let mut wrong = Vec::with_capacity(33);
        wrong.push(ED25519_TAG);
        wrong.extend_from_slice(&pk);
        let wrong_hash = blake2b_256(&wrong).unwrap();
        assert_ne!(good, wrong_hash);
    }
}
