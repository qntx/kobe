//! Ed25519 signing primitive shared by ed25519-dalek-backed chain signers.
//!
//! Wraps [`ed25519_dalek::SigningKey`]: deterministic RFC 8032 signing.
//! The inner key zeroizes on drop (ed25519-dalek's `zeroize` feature is
//! enabled in the workspace dependency), so no redundant secret copy is
//! kept. Every 32-byte string is a valid seed.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};

use crate::SecretKey;

/// Ed25519 signer.
///
/// Loads a 32-byte secret seed, exposes the derived public key, and
/// produces standard 64-byte Ed25519 signatures.
pub struct Ed25519Signer {
    key: SigningKey,
}

impl core::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519Signer")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Ed25519Signer {
    /// Create from a 32-byte secret seed. Infallible: every 32-byte string
    /// is a valid Ed25519 seed.
    #[must_use]
    pub fn new(secret: &SecretKey) -> Self {
        Self {
            key: SigningKey::from_bytes(secret.as_bytes()),
        }
    }

    /// 32-byte public key (raw Ed25519 point encoding).
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign arbitrary bytes with raw Ed25519 (no prefix or hashing).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    /// Verify a 64-byte Ed25519 signature against `message`.
    ///
    /// Malformed or cryptographically invalid input returns `false`; this
    /// method never fails.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.key
            .verifying_key()
            .verify(message, &Signature::from_bytes(signature))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 Test Vector 1 secret key.
    const KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    /// RFC 8032 Test Vector 1 public key.
    const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn fix() -> Ed25519Signer {
        let bytes = hex::decode(KEY_HEX).unwrap();
        Ed25519Signer::new(&SecretKey::from_bytes(&bytes).unwrap())
    }

    #[test]
    fn public_key_matches_rfc8032_tv1() {
        assert_eq!(hex::encode(fix().public_key()), PUBKEY_HEX);
    }

    #[test]
    fn every_32_byte_string_is_a_valid_seed() {
        let zero = SecretKey::from_bytes(&[0u8; 32]).unwrap();
        let signer = Ed25519Signer::new(&zero);
        assert_eq!(signer.sign(b"msg").len(), 64);
    }

    #[test]
    fn sign_is_deterministic_and_verifies() {
        let s = fix();
        let msg = b"authentic";
        let a = s.sign(msg);
        assert_eq!(a, s.sign(msg), "RFC 8032 signing is deterministic");
        assert!(s.verify(msg, &a));
    }

    #[test]
    fn verify_rejects_tampered_and_wrong_message() {
        let s = fix();
        let msg = b"authentic";
        let sig = s.sign(msg);
        assert!(!s.verify(b"different", &sig));

        let mut tampered = sig;
        tampered[0] ^= 1;
        assert!(!s.verify(msg, &tampered));
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let s = fix();
        let debug = alloc::format!("{s:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&KEY_HEX[..8]));
    }
}
