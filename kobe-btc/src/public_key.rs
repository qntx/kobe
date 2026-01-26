//! Bitcoin public key implementation.
//!
//! Implements `kobe::PublicKey` trait for unified wallet interface.

use crate::address::{AddressFormat, BtcAddress};
use crate::network::Network;
use k256::ecdsa::{SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier};
use kobe::{Error, Result, Signature};

use kobe::PublicKey as _;

/// Bitcoin public key based on secp256k1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcPublicKey {
    inner: VerifyingKey,
    compressed: bool,
}

impl BtcPublicKey {
    /// Create from a signing key.
    pub(crate) fn from_signing_key(key: &SigningKey, compressed: bool) -> Self {
        Self {
            inner: *key.verifying_key(),
            compressed,
        }
    }

    /// Create from raw compressed bytes (33 bytes).
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 {
            return Err(Error::InvalidLength {
                expected: 33,
                actual: bytes.len(),
            });
        }
        let inner = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self {
            inner,
            compressed: true,
        })
    }

    /// Create from raw uncompressed bytes (65 bytes).
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(Error::InvalidLength {
                expected: 65,
                actual: bytes.len(),
            });
        }
        let inner = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self {
            inner,
            compressed: false,
        })
    }

    /// Check if using compressed format.
    pub const fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// Serialize to compressed bytes (33 bytes).
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let point = self.inner.to_encoded_point(true);
        let mut result = [0u8; 33];
        result.copy_from_slice(point.as_bytes());
        result
    }
}

impl kobe::PublicKey for BtcPublicKey {
    type Address = BtcAddress;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Accept both compressed (33) and uncompressed (65) formats
        match bytes.len() {
            33 => Self::from_compressed_bytes(bytes),
            65 => Self::from_uncompressed_bytes(bytes),
            _ => Err(Error::InvalidLength {
                expected: 33,
                actual: bytes.len(),
            }),
        }
    }

    fn to_bytes(&self) -> [u8; 33] {
        self.to_compressed_bytes()
    }

    fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let point = self.inner.to_encoded_point(false);
        let mut result = [0u8; 65];
        result.copy_from_slice(point.as_bytes());
        result
    }

    fn to_address(&self) -> Self::Address {
        // Default to mainnet P2PKH for trait compatibility
        BtcAddress::from_public_key(self, Network::Mainnet, AddressFormat::P2PKH)
            .expect("P2PKH address creation should not fail")
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

impl BtcPublicKey {
    /// Get the x-only public key (32 bytes) for Taproot.
    ///
    /// This returns only the x-coordinate of the public key point,
    /// which is used in BIP-340 Schnorr signatures and P2TR addresses.
    pub fn to_x_only(&self) -> [u8; 32] {
        let point = self.inner.to_encoded_point(true);
        let bytes = point.as_bytes();
        let mut x_only = [0u8; 32];
        // Skip the prefix byte (0x02 or 0x03) and take only x-coordinate
        x_only.copy_from_slice(&bytes[1..33]);
        x_only
    }

    /// Check if the public key has an even y-coordinate.
    ///
    /// Used for Taproot to determine if key needs negation.
    pub fn has_even_y(&self) -> bool {
        let point = self.inner.to_encoded_point(true);
        let prefix = point.as_bytes()[0];
        prefix == 0x02
    }

    /// Get the hash160 of the public key (for P2PKH addresses).
    pub fn hash160(&self) -> [u8; 20] {
        let bytes = if self.compressed {
            self.to_compressed_bytes().to_vec()
        } else {
            self.to_uncompressed_bytes().to_vec()
        };
        kobe::hash::hash160(&bytes)
    }

    /// Derive a Bitcoin address.
    pub fn to_address(&self, network: Network, format: AddressFormat) -> Result<BtcAddress> {
        BtcAddress::from_public_key(self, network, format)
    }

    /// Verify a signature against a message hash.
    pub fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<()> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let sig =
            k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidSignature)?;

        self.inner
            .verify_prehash(hash, &sig)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Recover public key from signature and message hash.
    pub fn recover_from_prehash(
        hash: &[u8; 32],
        signature: &Signature,
        compressed: bool,
    ) -> Result<Self> {
        use k256::ecdsa::RecoveryId;

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let sig =
            k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidSignature)?;
        let recid = RecoveryId::from_byte(signature.v).ok_or(Error::InvalidSignature)?;

        let recovered = VerifyingKey::recover_from_prehash(hash, &sig, recid)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(Self {
            inner: recovered,
            compressed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BtcPrivateKey;
    use kobe::PrivateKey;

    #[test]
    fn test_public_key_derivation() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let private_key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let public_key = private_key.public_key();

        let compressed = public_key.to_compressed_bytes();
        assert_eq!(compressed.len(), 33);

        let recovered = BtcPublicKey::from_compressed_bytes(&compressed).unwrap();
        assert_eq!(
            public_key.to_compressed_bytes(),
            recovered.to_compressed_bytes()
        );
    }
}
