//! secp256k1 ECDSA primitive shared by k256-backed chain signers.
//!
//! Wraps [`k256::ecdsa::SigningKey`]: RFC 6979 deterministic signing with
//! low-S normalization, recoverable or DER output. The inner key zeroizes
//! its scalar on drop (`ecdsa::SigningKey` implements `ZeroizeOnDrop` in
//! ecdsa 0.17), so no redundant secret copy is kept.

use alloc::vec::Vec;

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey};

use crate::{Error, RecoverableSignature, SecretKey};

/// secp256k1 ECDSA signer.
///
/// Produces recoverable (`r || s` plus recovery parity) or DER-encoded
/// signatures over a 32-byte pre-hashed digest.
pub struct Secp256k1Signer {
    key: SigningKey,
}

impl core::fmt::Debug for Secp256k1Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Secp256k1Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Secp256k1Signer {
    /// Create from a 32-byte secret.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the secret is not a valid secp256k1
    /// scalar (zero or ≥ the curve order).
    pub fn new(secret: &SecretKey) -> Result<Self, Error> {
        let key = SigningKey::from_slice(secret.as_bytes())
            .map_err(|e| Error::Crypto(alloc::format!("invalid secp256k1 scalar: {e}")))?;
        Ok(Self { key })
    }

    /// Compressed SEC1-encoded public key (33 bytes, leading `0x02` or `0x03`).
    #[must_use]
    pub fn compressed_public_key(&self) -> [u8; 33] {
        let point = self.key.verifying_key().to_sec1_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Uncompressed SEC1-encoded public key (65 bytes, leading `0x04`).
    #[must_use]
    pub fn uncompressed_public_key(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_sec1_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Sign a 32-byte pre-hashed digest with recoverable ECDSA.
    ///
    /// Deterministic (RFC 6979) and normalized to low-S. The returned
    /// recovery id is the raw parity `0` or `1`; chain wire headers add
    /// their own offsets.
    #[must_use]
    pub fn sign_recoverable(&self, digest: &[u8; 32]) -> RecoverableSignature {
        let (sig, rid) = self.key.sign_prehash_recoverable(digest);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig.to_bytes());
        RecoverableSignature {
            signature,
            recovery: rid.to_byte(),
        }
    }

    /// Sign a 32-byte pre-hashed digest, returning the ASN.1 DER encoding.
    ///
    /// Variable length (typically 70–72 bytes). No recovery id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the signing primitive fails.
    pub fn sign_der(&self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let sig: Signature = self
            .key
            .sign_prehash(digest)
            .map_err(|e| Error::Crypto(alloc::format!("secp256k1 sign failed: {e}")))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// Verify a compact (64-byte) or recoverable (65-byte) ECDSA signature
    /// against a 32-byte pre-hashed digest.
    ///
    /// The trailing `v` byte of a 65-byte signature is ignored — only the
    /// leading 64 bytes are checked. Malformed input returns `false`;
    /// this method never fails.
    #[must_use]
    pub fn verify(&self, digest: &[u8; 32], signature: &[u8]) -> bool {
        let Some(compact) = (match signature.len() {
            64 => Some(signature),
            65 => signature.get(..64),
            _ => None,
        }) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(compact) else {
            return false;
        };
        self.key
            .verifying_key()
            .verify_prehash(digest, &sig)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    const TEST_DIGEST: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    fn fix() -> Secp256k1Signer {
        let bytes = hex::decode(KEY_HEX).unwrap();
        Secp256k1Signer::new(&SecretKey::from_bytes(&bytes).unwrap()).unwrap()
    }

    #[test]
    fn new_rejects_zero_and_curve_order() {
        let zero = SecretKey::from_bytes(&[0u8; 32]).unwrap();
        assert!(matches!(Secp256k1Signer::new(&zero), Err(Error::Crypto(_))));

        // `n` (the curve order) is also forbidden — k256 rejects `>= n`.
        let n: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let key = SecretKey::from_bytes(&n).unwrap();
        assert!(matches!(Secp256k1Signer::new(&key), Err(Error::Crypto(_))));
    }

    #[test]
    fn public_key_widths() {
        let s = fix();
        let compressed = s.compressed_public_key();
        let uncompressed = s.uncompressed_public_key();
        assert_eq!(compressed.len(), 33);
        assert_eq!(uncompressed.len(), 65);
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
        assert_eq!(uncompressed[0], 0x04);
        assert_eq!(compressed[1..], uncompressed[1..33]);
    }

    #[test]
    fn sign_recoverable_output_is_65_bytes_with_raw_parity() {
        let s = fix();
        let out = s.sign_recoverable(&TEST_DIGEST);
        let bytes = out.to_bytes();
        assert_eq!(bytes.len(), 65, "r || s || recovery");
        assert!(out.recovery <= 1, "raw parity, not wire-format header");
        // Low-S by default (k256 enforces it); high bit of `s` must be 0.
        assert_eq!(out.signature[32] >> 7, 0, "k256 returns low-S scalars");
    }

    #[test]
    fn sign_der_output_is_asn1_der() {
        let s = fix();
        let der = s.sign_der(&TEST_DIGEST).unwrap();
        assert_eq!(der.first(), Some(&0x30), "DER SEQUENCE tag");
        assert!(
            (8..=72).contains(&der.len()),
            "DER ECDSA is typically 70-72 bytes, got {}",
            der.len(),
        );
    }

    #[test]
    fn verify_accepts_64_and_65_byte_signatures() {
        let s = fix();
        let out = s.sign_recoverable(&TEST_DIGEST);
        let bytes = out.to_bytes();
        assert!(s.verify(&TEST_DIGEST, &out.signature));
        assert!(s.verify(&TEST_DIGEST, &bytes));

        // Any other length or malformed content is rejected, never an error.
        assert!(!s.verify(&TEST_DIGEST, &[0u8; 63]));
        assert!(!s.verify(&TEST_DIGEST, &[0u8; 66]));
        assert!(!s.verify(&TEST_DIGEST, &[0u8; 64]));
    }

    #[test]
    fn verify_rejects_wrong_digest_and_tampered_signature() {
        let s = fix();
        let out = s.sign_recoverable(&TEST_DIGEST);

        let mut wrong = TEST_DIGEST;
        wrong[0] ^= 1;
        assert!(!s.verify(&wrong, &out.signature));

        let mut tampered = out.signature;
        tampered[32] ^= 1;
        assert!(!s.verify(&TEST_DIGEST, &tampered));
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let s = fix();
        let debug = alloc::format!("{s:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&KEY_HEX[..8]));
    }
}
