//! BIP-32 Extended Public Key for Bitcoin.
//!
//! Implements `kobe::ExtendedPublicKey` trait for watch-only wallet support.
//! Supports non-hardened child derivation and xpub serialization.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey as K256PublicKey};
use sha2::Sha512;

use kobe::{Error, Result};

use crate::network::Network;
use crate::pubkey::PublicKey;
use crate::xpriv::ExtendedPrivateKey;

#[cfg(feature = "alloc")]
use alloc::string::String;

type HmacSha512 = Hmac<Sha512>;

/// BIP-32 Extended Public Key for Bitcoin.
///
/// Used for watch-only wallets and deriving addresses without private keys.
/// Only supports non-hardened child derivation.
#[derive(Clone)]
pub struct ExtendedPublicKey {
    /// The underlying public key
    public_key: PublicKey,
    /// Chain code for key derivation
    chain_code: [u8; 32],
    /// Depth in the derivation tree (0 for master)
    depth: u8,
    /// Parent key fingerprint (first 4 bytes of hash160 of parent public key)
    parent_fingerprint: [u8; 4],
    /// Child index that produced this key
    child_index: u32,
    /// Network (mainnet or testnet)
    network: Network,
}

impl kobe::ExtendedPublicKey for ExtendedPublicKey {
    type PublicKey = PublicKey;

    fn from_extended_private_key<E: kobe::ExtendedPrivateKey>(xprv: &E) -> Result<Self>
    where
        E::PrivateKey: kobe::PrivateKey<PublicKey = Self::PublicKey>,
    {
        // Get public key from private key
        let public_key = kobe::PrivateKey::public_key(&xprv.private_key());

        Ok(Self {
            public_key,
            chain_code: xprv.chain_code(),
            depth: xprv.depth(),
            parent_fingerprint: [0u8; 4], // Will be set correctly in Bitcoin-specific method
            child_index: 0,
            network: Network::Mainnet,
        })
    }

    fn derive_child(&self, index: u32) -> Result<Self> {
        // Only non-hardened derivation is supported
        if index >= 0x80000000 {
            return Err(Error::HardenedDerivationRequired);
        }

        self.derive_child_internal(index)
    }

    #[cfg(feature = "alloc")]
    fn derive_path(&self, path: &str) -> Result<Self> {
        self.derive(path)
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

impl ExtendedPublicKey {
    /// Creates an extended public key from an extended private key with network.
    pub fn from_extended_private_key_with_network(
        xprv: &ExtendedPrivateKey,
        network: Network,
    ) -> Self {
        use kobe::ExtendedPrivateKey as _;
        Self {
            public_key: xprv.public_key(),
            chain_code: xprv.chain_code(),
            depth: xprv.depth(),
            parent_fingerprint: *xprv.parent_fingerprint(),
            child_index: xprv.child_index().to_u32(),
            network,
        }
    }

    /// Derive a child key at the given index (non-hardened only).
    fn derive_child_internal(&self, index: u32) -> Result<Self> {
        if self.depth == 255 {
            return Err(Error::MaxDepthExceeded);
        }

        // Non-hardened derivation: HMAC-SHA512(Key = chainCode, Data = serP(Kpar) || ser32(i))
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

        // Get parent public key as a point
        let parent_bytes = kobe::PublicKey::to_bytes(&self.public_key);
        let parent_key =
            K256PublicKey::from_sec1_bytes(&parent_bytes).map_err(|_| Error::InvalidPublicKey)?;
        let parent_point = ProjectivePoint::from(parent_key.as_affine());

        // Add points
        let child_point = il_point + parent_point;
        let child_affine = child_point.to_affine();

        // Convert back to public key
        let child_encoded = child_affine.to_encoded_point(true);
        let child_public_key = PublicKey::from_compressed_bytes(child_encoded.as_bytes())
            .map_err(|_| Error::InvalidPublicKey)?;

        // Compute parent fingerprint
        let parent_hash = kobe::hash::hash160(&parent_bytes);
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&parent_hash[..4]);

        // Child chain code
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        Ok(Self {
            public_key: child_public_key,
            chain_code,
            depth: self.depth + 1,
            parent_fingerprint,
            child_index: index,
            network: self.network,
        })
    }

    /// Derives a child key from a path string (e.g., "m/0/1/2").
    ///
    /// Only supports non-hardened paths. Hardened derivation requires private key.
    #[cfg(feature = "alloc")]
    pub fn derive(&self, path: &str) -> Result<Self> {
        let path = path.trim();

        // Handle paths starting with "m/" or "M/"
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

            // Check for hardened marker - not allowed for xpub
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

    /// Get the network.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Serialize to xpub format (Base58Check encoded).
    #[cfg(feature = "alloc")]
    pub fn to_xpub(&self) -> String {
        let version = match self.network {
            Network::Mainnet => [0x04, 0x88, 0xB2, 0x1E], // xpub
            Network::Testnet => [0x04, 0x35, 0x87, 0xCF], // tpub
        };

        let mut data = [0u8; 78];
        data[0..4].copy_from_slice(&version);
        data[4] = self.depth;
        data[5..9].copy_from_slice(&self.parent_fingerprint);
        data[9..13].copy_from_slice(&self.child_index.to_be_bytes());
        data[13..45].copy_from_slice(&self.chain_code);
        data[45..78].copy_from_slice(&kobe::PublicKey::to_bytes(&self.public_key));

        // Add checksum and encode
        let checksum = kobe::hash::double_sha256(&data);
        let mut with_checksum = [0u8; 82];
        with_checksum[..78].copy_from_slice(&data);
        with_checksum[78..82].copy_from_slice(&checksum[..4]);

        bs58::encode(&with_checksum).into_string()
    }

    /// Parse from xpub format (Base58Check encoded).
    #[cfg(feature = "alloc")]
    pub fn from_xpub(xpub: &str) -> Result<Self> {
        let decoded = bs58::decode(xpub)
            .into_vec()
            .map_err(|_| Error::InvalidEncoding)?;

        if decoded.len() != 82 {
            return Err(Error::InvalidLength {
                expected: 82,
                actual: decoded.len(),
            });
        }

        // Verify checksum
        let checksum = kobe::hash::double_sha256(&decoded[..78]);
        if checksum[..4] != decoded[78..82] {
            return Err(Error::InvalidChecksum);
        }

        // Parse version
        let version = &decoded[0..4];
        let network = match version {
            [0x04, 0x88, 0xB2, 0x1E] => Network::Mainnet, // xpub
            [0x04, 0x35, 0x87, 0xCF] => Network::Testnet, // tpub
            _ => return Err(Error::InvalidEncoding),
        };

        let depth = decoded[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&decoded[5..9]);
        let child_index = u32::from_be_bytes([decoded[9], decoded[10], decoded[11], decoded[12]]);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&decoded[13..45]);

        let public_key = PublicKey::from_compressed_bytes(&decoded[45..78])
            .map_err(|_| Error::InvalidPublicKey)?;

        Ok(Self {
            public_key,
            chain_code,
            depth,
            parent_fingerprint,
            child_index,
            network,
        })
    }
}

impl core::fmt::Debug for ExtendedPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedPublicKey")
            .field("depth", &self.depth)
            .field("child_index", &self.child_index)
            .field("network", &self.network)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kobe::ExtendedPublicKey as _;

    // BIP-32 test vector 1
    const TEST_SEED_1: &[u8] = &hex_literal::hex!("000102030405060708090a0b0c0d0e0f");

    #[test]
    fn test_xpub_from_xprv() {
        let xprv =
            ExtendedPrivateKey::from_seed_with_network(TEST_SEED_1, Network::Mainnet).unwrap();
        let xpub =
            ExtendedPublicKey::from_extended_private_key_with_network(&xprv, Network::Mainnet);

        assert_eq!(xpub.depth(), 0);
        assert_eq!(xpub.child_index(), 0);
    }

    #[test]
    fn test_xpub_serialization() {
        let xprv =
            ExtendedPrivateKey::from_seed_with_network(TEST_SEED_1, Network::Mainnet).unwrap();
        let xpub =
            ExtendedPublicKey::from_extended_private_key_with_network(&xprv, Network::Mainnet);

        let serialized = xpub.to_xpub();
        assert!(serialized.starts_with("xpub"));

        // Roundtrip
        let recovered = ExtendedPublicKey::from_xpub(&serialized).unwrap();
        assert_eq!(xpub.to_xpub(), recovered.to_xpub());
    }

    #[test]
    fn test_xpub_bip32_vector1() {
        let xprv =
            ExtendedPrivateKey::from_seed_with_network(TEST_SEED_1, Network::Mainnet).unwrap();
        let xpub =
            ExtendedPublicKey::from_extended_private_key_with_network(&xprv, Network::Mainnet);

        // BIP-32 test vector 1 chain m expected xpub
        assert_eq!(
            xpub.to_xpub(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
    }

    #[test]
    fn test_xpub_derive_non_hardened() {
        let xprv =
            ExtendedPrivateKey::from_seed_with_network(TEST_SEED_1, Network::Mainnet).unwrap();

        // First derive hardened from xprv, then get xpub
        let xprv_child = xprv
            .derive_child_index(crate::ChildIndex::Hardened(0))
            .unwrap();
        let xpub = ExtendedPublicKey::from_extended_private_key_with_network(
            &xprv_child,
            Network::Mainnet,
        );

        // Now derive non-hardened from xpub
        let xpub_child = xpub.derive_child(1).unwrap();
        assert_eq!(xpub_child.depth(), 2);

        // Compare with derivation from xprv
        let xprv_grandchild = xprv_child
            .derive_child_index(crate::ChildIndex::Normal(1))
            .unwrap();
        let xpub_from_prv = ExtendedPublicKey::from_extended_private_key_with_network(
            &xprv_grandchild,
            Network::Mainnet,
        );

        assert_eq!(xpub_child.to_xpub(), xpub_from_prv.to_xpub());
    }

    #[test]
    fn test_xpub_hardened_fails() {
        let xprv =
            ExtendedPrivateKey::from_seed_with_network(TEST_SEED_1, Network::Mainnet).unwrap();
        let xpub =
            ExtendedPublicKey::from_extended_private_key_with_network(&xprv, Network::Mainnet);

        // Hardened derivation should fail
        let result = xpub.derive_child(0x80000000);
        assert!(result.is_err());
    }

    #[test]
    fn test_xpub_derive_path() {
        let xprv =
            ExtendedPrivateKey::from_seed_with_network(TEST_SEED_1, Network::Mainnet).unwrap();
        let xpub =
            ExtendedPublicKey::from_extended_private_key_with_network(&xprv, Network::Mainnet);

        // Non-hardened path should work
        let derived = xpub.derive("m/0/1/2").unwrap();
        assert_eq!(derived.depth(), 3);

        // Hardened path should fail
        let result = xpub.derive("m/0'/1/2");
        assert!(result.is_err());
    }

    #[test]
    fn test_testnet_tpub() {
        let xprv =
            ExtendedPrivateKey::from_seed_with_network(TEST_SEED_1, Network::Testnet).unwrap();
        let xpub =
            ExtendedPublicKey::from_extended_private_key_with_network(&xprv, Network::Testnet);

        let tpub = xpub.to_xpub();
        assert!(tpub.starts_with("tpub"));
    }
}
