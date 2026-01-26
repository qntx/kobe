//! Ethereum public key implementation.
//!
//! Implements `kobe::PublicKey` trait for unified wallet interface.

use k256::ecdsa::{VerifyingKey, signature::hazmat::PrehashVerifier};

use kobe::{Error, Result, Signature};

use crate::address::Address;
use crate::eip191;

/// Ethereum public key based on secp256k1.
///
/// Supports compressed and uncompressed formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    inner: VerifyingKey,
}

impl PublicKey {
    /// Create from a verifying key.
    pub(crate) fn from_verifying_key(key: VerifyingKey) -> Self {
        Self { inner: key }
    }

    /// Get the raw 64-byte public key (without 0x04 prefix).
    #[inline]
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let uncompressed = kobe::PublicKey::to_uncompressed_bytes(self);
        let mut result = [0u8; 64];
        result.copy_from_slice(&uncompressed[1..]);
        result
    }
}

impl kobe::PublicKey for PublicKey {
    type Address = Address;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> [u8; 33] {
        let point = self.inner.to_encoded_point(true);
        let mut result = [0u8; 33];
        result.copy_from_slice(point.as_bytes());
        result
    }

    fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let point = self.inner.to_encoded_point(false);
        let mut result = [0u8; 65];
        result.copy_from_slice(point.as_bytes());
        result
    }

    fn to_address(&self) -> Self::Address {
        Address::from_public_key(self)
    }

    fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<()> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let sig =
            k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidSignature)?;

        self.inner
            .verify_prehash(hash, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl PublicKey {
    /// Recover public key from signature and message hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or recovery fails.
    pub fn recover_from_prehash(hash: &[u8; 32], signature: &Signature) -> Result<Self> {
        use k256::ecdsa::RecoveryId;

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let sig =
            k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidSignature)?;
        let recid = RecoveryId::from_byte(signature.v).ok_or(Error::InvalidSignature)?;

        let recovered = VerifyingKey::recover_from_prehash(hash, &sig, recid)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(Self { inner: recovered })
    }

    /// Recover public key from an EIP-191 personal signed message.
    ///
    /// This is the inverse of `PrivateKey::sign_message`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or recovery fails.
    pub fn recover_from_message(message: &[u8], signature: &Signature) -> Result<Self> {
        let hash = eip191::hash_message(message);
        Self::recover_from_prehash(&hash, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privkey::PrivateKey;
    use kobe::PrivateKey as PrivateKeyTrait;

    #[test]
    fn test_public_key_derivation() {
        let private_key: PrivateKey =
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                .parse()
                .unwrap();
        let public_key = <PrivateKey as PrivateKeyTrait>::public_key(&private_key);
        let compressed = kobe::PublicKey::to_bytes(&public_key);
        assert_eq!(compressed.len(), 33);

        let recovered = <PublicKey as kobe::PublicKey>::from_bytes(&compressed).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_sign_and_verify() {
        let private_key: PrivateKey =
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                .parse()
                .unwrap();
        let public_key = <PrivateKey as PrivateKeyTrait>::public_key(&private_key);

        let hash = [0u8; 32];
        let signature = <PrivateKey as PrivateKeyTrait>::sign_prehash(&private_key, &hash).unwrap();

        kobe::PublicKey::verify(&public_key, &hash, &signature).unwrap();
    }

    #[test]
    fn test_recover() {
        let private_key: PrivateKey =
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                .parse()
                .unwrap();
        let public_key = <PrivateKey as PrivateKeyTrait>::public_key(&private_key);

        let hash = [1u8; 32];
        let signature = <PrivateKey as PrivateKeyTrait>::sign_prehash(&private_key, &hash).unwrap();

        let recovered = PublicKey::recover_from_prehash(&hash, &signature).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_recover_from_message() {
        let private_key: PrivateKey =
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                .parse()
                .unwrap();
        let expected_address = private_key.address();

        let message = b"Hello, Ethereum!";
        let signature = private_key.sign_message(message).unwrap();

        // Recover public key from message signature
        let recovered = PublicKey::recover_from_message(message, &signature).unwrap();
        let recovered_address = kobe::PublicKey::to_address(&recovered);

        assert_eq!(expected_address, recovered_address);
    }
}
