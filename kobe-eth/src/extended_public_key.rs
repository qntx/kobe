//! BIP-32 Extended Public Key for Ethereum.
//!
//! Implements `kobe::ExtendedPublicKey` trait for watch-only wallet support.
//! Supports non-hardened child derivation.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey as K256PublicKey};
use sha2::Sha512;

use kobe::{Error, PublicKey as _, Result};

use crate::address::EthAddress;
use crate::extended_key::EthExtendedPrivateKey;
use crate::public_key::EthPublicKey;

type HmacSha512 = Hmac<Sha512>;

/// BIP-32 Extended Public Key for Ethereum.
///
/// Used for watch-only wallets and deriving addresses without private keys.
/// Only supports non-hardened child derivation.
#[derive(Clone)]
pub struct EthExtendedPublicKey {
    /// The underlying public key
    public_key: EthPublicKey,
    /// Chain code for key derivation
    chain_code: [u8; 32],
    /// Depth in the derivation tree (0 for master)
    depth: u8,
    /// Parent key fingerprint (first 4 bytes of hash160 of parent public key)
    parent_fingerprint: [u8; 4],
    /// Child index that produced this key
    child_index: u32,
}

impl kobe::ExtendedPublicKey for EthExtendedPublicKey {
    type PublicKey = EthPublicKey;

    fn from_extended_private_key<E: kobe::ExtendedPrivateKey>(xprv: &E) -> Result<Self>
    where
        E::PrivateKey: kobe::PrivateKey<PublicKey = Self::PublicKey>,
    {
        let public_key = kobe::PrivateKey::public_key(&xprv.private_key());

        Ok(Self {
            public_key,
            chain_code: xprv.chain_code(),
            depth: xprv.depth(),
            parent_fingerprint: [0u8; 4],
            child_index: 0,
        })
    }

    fn derive_child(&self, index: u32) -> Result<Self> {
        if index >= 0x80000000 {
            return Err(Error::HardenedDerivationRequired);
        }

        self.derive_child_internal(index)
    }

    #[cfg(feature = "alloc")]
    fn derive_path(&self, path: &str) -> Result<Self> {
        self.derive_path_str(path)
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    fn depth(&self) -> u8 {
        self.depth
    }

    fn parent_fingerprint(&self) -> [u8; 4] {
        self.parent_fingerprint
    }

    fn child_index(&self) -> u32 {
        self.child_index
    }
}

impl EthExtendedPublicKey {
    /// Create from an extended private key.
    pub fn from_extended_private_key_internal(xprv: &EthExtendedPrivateKey) -> Self {
        use kobe::ExtendedPrivateKey as _;

        Self {
            public_key: xprv.public_key(),
            chain_code: xprv.chain_code(),
            depth: xprv.depth(),
            parent_fingerprint: *xprv.parent_fingerprint(),
            child_index: xprv.child_index(),
        }
    }

    /// Derive a child key at the given index (non-hardened only).
    fn derive_child_internal(&self, index: u32) -> Result<Self> {
        if self.depth == 255 {
            return Err(Error::MaxDepthExceeded);
        }

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).map_err(|_| Error::CryptoError)?;

        mac.update(&kobe::PublicKey::to_bytes(&self.public_key));
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();
        let il = &result[..32];
        let ir = &result[32..];

        // Compute child public key: Ki = point(parse256(IL)) + Kpar
        let il_scalar = k256::NonZeroScalar::try_from(il).map_err(|_| Error::InvalidPrivateKey)?;
        let il_point = ProjectivePoint::GENERATOR * il_scalar.as_ref();

        let parent_bytes = kobe::PublicKey::to_bytes(&self.public_key);
        let parent_key =
            K256PublicKey::from_sec1_bytes(&parent_bytes).map_err(|_| Error::InvalidPublicKey)?;
        let parent_point = ProjectivePoint::from(parent_key.as_affine());

        let child_point = il_point + parent_point;
        let child_affine = child_point.to_affine();

        let child_encoded = child_affine.to_encoded_point(true);
        let child_public_key = EthPublicKey::from_bytes(child_encoded.as_bytes())
            .map_err(|_| Error::InvalidPublicKey)?;

        let parent_hash = kobe::hash::hash160(&parent_bytes);
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&parent_hash[..4]);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        Ok(Self {
            public_key: child_public_key,
            chain_code,
            depth: self.depth + 1,
            parent_fingerprint,
            child_index: index,
        })
    }

    /// Derive from a path string (e.g., "m/0/1/2").
    ///
    /// Only supports non-hardened paths.
    #[cfg(feature = "alloc")]
    pub fn derive_path_str(&self, path: &str) -> Result<Self> {
        let path = path.trim();

        let path = if path.starts_with("m/") || path.starts_with("M/") {
            &path[2..]
        } else if path == "m" || path == "M" {
            return Ok(self.clone());
        } else {
            path
        };

        let mut current = self.clone();

        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }

            if component.ends_with('\'') || component.ends_with('h') {
                return Err(Error::HardenedDerivationRequired);
            }

            let index: u32 = component
                .parse()
                .map_err(|_| Error::InvalidDerivationPath)?;

            current = current.derive_child_internal(index)?;
        }

        Ok(current)
    }

    /// Get the corresponding Ethereum address.
    pub fn address(&self) -> EthAddress {
        EthAddress::from_public_key(&self.public_key)
    }

    /// Get a reference to the public key.
    pub fn public_key_ref(&self) -> &EthPublicKey {
        &self.public_key
    }

    /// Get a reference to the chain code.
    pub fn chain_code_ref(&self) -> &[u8; 32] {
        &self.chain_code
    }
}

impl core::fmt::Debug for EthExtendedPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EthExtendedPublicKey")
            .field("depth", &self.depth)
            .field("child_index", &self.child_index)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kobe::ExtendedPrivateKey as _;
    use kobe::ExtendedPublicKey as _;

    const TEST_SEED_1: &[u8] = &hex_literal::hex!("000102030405060708090a0b0c0d0e0f");

    #[test]
    fn test_xpub_from_xprv() {
        let xprv = crate::EthExtendedPrivateKey::from_seed(TEST_SEED_1).unwrap();
        let xpub = EthExtendedPublicKey::from_extended_private_key_internal(&xprv);

        assert_eq!(xpub.depth(), 0);
        assert_eq!(xpub.child_index(), 0);
    }

    #[test]
    fn test_xpub_derive_non_hardened() {
        let xprv = crate::EthExtendedPrivateKey::from_seed(TEST_SEED_1).unwrap();

        // First derive hardened from xprv
        let xprv_child = xprv.derive_child_hardened(44).unwrap();
        let xpub = EthExtendedPublicKey::from_extended_private_key_internal(&xprv_child);

        // Now derive non-hardened from xpub
        let xpub_child = xpub.derive_child(0).unwrap();
        assert_eq!(xpub_child.depth(), 2);

        // Compare with derivation from xprv
        let xprv_grandchild = xprv_child.derive_child(0).unwrap();
        let xpub_from_prv =
            EthExtendedPublicKey::from_extended_private_key_internal(&xprv_grandchild);

        // Public keys should match
        assert_eq!(
            kobe::PublicKey::to_bytes(&xpub_child.public_key()),
            kobe::PublicKey::to_bytes(&xpub_from_prv.public_key())
        );
    }

    #[test]
    fn test_xpub_hardened_fails() {
        let xprv = crate::EthExtendedPrivateKey::from_seed(TEST_SEED_1).unwrap();
        let xpub = EthExtendedPublicKey::from_extended_private_key_internal(&xprv);

        let result = xpub.derive_child(0x80000000);
        assert!(result.is_err());
    }

    #[test]
    fn test_xpub_derive_path() {
        let xprv = crate::EthExtendedPrivateKey::from_seed(TEST_SEED_1).unwrap();
        let xpub = EthExtendedPublicKey::from_extended_private_key_internal(&xprv);

        // Non-hardened path should work
        let derived = xpub.derive_path_str("m/0/1/2").unwrap();
        assert_eq!(derived.depth(), 3);

        // Hardened path should fail
        let result = xpub.derive_path_str("m/0'/1/2");
        assert!(result.is_err());
    }

    #[test]
    fn test_xpub_address() {
        let xprv = crate::EthExtendedPrivateKey::from_seed(TEST_SEED_1).unwrap();
        let xpub = EthExtendedPublicKey::from_extended_private_key_internal(&xprv);

        // Should be able to derive an address
        let _addr = xpub.address();
    }
}
