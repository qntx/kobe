//! BIP-340 Schnorr signing primitive for secp256k1.
//!
//! Wraps [`k256::schnorr::SigningKey`], which zeroizes on drop (k256 0.14),
//! so no redundant secret copy is kept. Both [`sign`](SchnorrSigner::sign)
//! and [`verify`](SchnorrSigner::verify) operate on the raw message bytes —
//! no implicit hashing, so arbitrary-length messages are allowed. Public
//! keys are 32-byte x-only values (parity byte stripped); the inner key may
//! internally negate the scalar per BIP-340 when the y coordinate is odd.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};

use crate::{Error, SecretKey};

/// BIP-340 Schnorr signer over secp256k1 (Taproot / NIP-01 style).
///
/// `aux_rand` is caller-supplied auxiliary randomness — a pure function
/// input, never sampled internally.
pub struct SchnorrSigner {
    key: SigningKey,
}

impl core::fmt::Debug for SchnorrSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SchnorrSigner")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl SchnorrSigner {
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

    /// 32-byte BIP-340 x-only public key (parity byte stripped).
    #[must_use]
    pub fn xonly_public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes().into()
    }

    /// Sign `message` bytes directly with BIP-340 Schnorr.
    ///
    /// The message is used verbatim as the `m` input of BIP-340 — no
    /// implicit SHA-256 is applied. `aux_rand` is the caller-supplied
    /// BIP-340 auxiliary randomness; `[0u8; 32]` gives deterministic output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if the signing primitive fails.
    pub fn sign(&self, message: &[u8], aux_rand: &[u8; 32]) -> Result<[u8; 64], Error> {
        self.key
            .sign_raw(message, aux_rand)
            .map_err(|e| Error::Crypto(alloc::format!("schnorr sign failed: {e}")))
            .map(|sig| sig.to_bytes())
    }

    /// Verify a 64-byte BIP-340 Schnorr signature against `message`.
    ///
    /// Malformed or cryptographically invalid input returns `false`; this
    /// method never fails.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        Self::verify_with(&self.xonly_public_key(), message, signature)
    }

    /// Verify a BIP-340 signature under an arbitrary x-only public key.
    ///
    /// Malformed public key or signature returns `false`; never fails.
    #[must_use]
    pub fn verify_with(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_slice(public_key) else {
            return false;
        };
        let Ok(sig) = Signature::try_from(signature.as_slice()) else {
            return false;
        };
        vk.verify_raw(message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIP-06 Test Vector 1 secret key (valid BIP-340 scalar).
    const KEY_HEX: &str = "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a";
    const XONLY_HEX: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
    const ZERO_AUX: [u8; 32] = [0u8; 32];

    fn fix() -> SchnorrSigner {
        let bytes = hex::decode(KEY_HEX).unwrap();
        SchnorrSigner::new(&SecretKey::from_bytes(&bytes).unwrap()).unwrap()
    }

    #[test]
    fn xonly_public_key_matches_nip06_tv1() {
        assert_eq!(hex::encode(fix().xonly_public_key()), XONLY_HEX);
    }

    #[test]
    fn new_rejects_zero_scalar() {
        let zero = SecretKey::from_bytes(&[0u8; 32]).unwrap();
        assert!(matches!(SchnorrSigner::new(&zero), Err(Error::Crypto(_))));
    }

    #[test]
    fn sign_is_deterministic_and_verifies() {
        let s = fix();
        let msg = b"BIP-340 deterministic";
        let a = s.sign(msg, &ZERO_AUX).unwrap();
        let b = s.sign(msg, &ZERO_AUX).unwrap();
        assert_eq!(a, b, "aux_rand = 0 is deterministic");
        assert_eq!(a.len(), 64);
        assert!(s.verify(msg, &a));
    }

    #[test]
    fn verify_rejects_tampered_and_wrong_message() {
        let s = fix();
        let msg = b"authentic";
        let sig = s.sign(msg, &ZERO_AUX).unwrap();
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
