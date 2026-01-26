//! BIP-32 Hierarchical Deterministic (HD) key derivation.

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::address::{AddressFormat, BtcAddress};
use crate::network::Network;
use crate::private_key::BtcPrivateKey;
use crate::public_key::BtcPublicKey;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::ops::Reduce;
use k256::{Scalar, U256};
use kobe::{Error, Result};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// Child key index for BIP-32 derivation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildIndex {
    /// Normal (non-hardened) derivation: 0 to 2^31 - 1
    Normal(u32),
    /// Hardened derivation: 2^31 to 2^32 - 1
    Hardened(u32),
}

impl ChildIndex {
    /// Hardened index offset (2^31)
    pub const HARDENED_OFFSET: u32 = 0x80000000;

    /// Create a normal child index.
    pub const fn normal(index: u32) -> Self {
        Self::Normal(index)
    }

    /// Create a hardened child index.
    pub const fn hardened(index: u32) -> Self {
        Self::Hardened(index)
    }

    /// Convert to the raw u32 value used in derivation.
    pub const fn to_u32(&self) -> u32 {
        match self {
            Self::Normal(i) => *i,
            Self::Hardened(i) => *i | Self::HARDENED_OFFSET,
        }
    }

    /// Check if this is a hardened index.
    pub const fn is_hardened(&self) -> bool {
        matches!(self, Self::Hardened(_))
    }
}

impl From<u32> for ChildIndex {
    fn from(value: u32) -> Self {
        if value >= Self::HARDENED_OFFSET {
            Self::Hardened(value & !Self::HARDENED_OFFSET)
        } else {
            Self::Normal(value)
        }
    }
}

/// BIP-32 Extended Private Key.
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    /// The underlying private key
    private_key: BtcPrivateKey,
    /// Chain code for key derivation
    chain_code: [u8; 32],
    /// Depth in the derivation tree (0 for master)
    depth: u8,
    /// Parent key fingerprint (first 4 bytes of hash160 of parent public key)
    parent_fingerprint: [u8; 4],
    /// Child index that produced this key
    child_index: ChildIndex,
    /// Network (mainnet or testnet)
    network: Network,
}

impl Zeroize for ExtendedPrivateKey {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
        self.chain_code.zeroize();
        self.depth = 0;
        self.parent_fingerprint.zeroize();
    }
}

impl Drop for ExtendedPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ExtendedPrivateKey {
    /// Create master key from seed (BIP-32).
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(Error::InvalidLength {
                expected: 32,
                actual: seed.len(),
            });
        }

        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").map_err(|_| Error::CryptoError)?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        // First 32 bytes are the private key, last 32 are the chain code
        let private_key = BtcPrivateKey::from_bytes(&result[..32])?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self {
            private_key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: ChildIndex::Normal(0),
            network,
        })
    }

    /// Derive a child key at the given index.
    pub fn derive_child(&self, index: ChildIndex) -> Result<Self> {
        if self.depth == 255 {
            return Err(Error::MaxDepthExceeded);
        }

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).map_err(|_| Error::CryptoError)?;

        match index {
            ChildIndex::Normal(_) => {
                // For normal derivation: HMAC-SHA512(Key = chainCode, Data = serP(point(kpar)) || ser32(i))
                let pubkey = self.private_key.public_key();
                mac.update(&pubkey.to_compressed_bytes());
            }
            ChildIndex::Hardened(_) => {
                // For hardened derivation: HMAC-SHA512(Key = chainCode, Data = 0x00 || ser256(kpar) || ser32(i))
                mac.update(&[0u8]);
                mac.update(&self.private_key.to_bytes());
            }
        }

        mac.update(&index.to_u32().to_be_bytes());
        let result = mac.finalize().into_bytes();

        // Parse IL as 256-bit number and add to parent key
        let il = &result[..32];
        let ir = &result[32..];

        // Create child key: child = parse256(IL) + parent (mod n)
        // Convert bytes to U256 and then reduce to Scalar
        let parent_bytes = self.private_key.to_bytes();
        let parent_uint = U256::from_be_slice(&parent_bytes);
        let parent_scalar: Scalar = <Scalar as Reduce<U256>>::reduce(parent_uint);

        let il_uint = U256::from_be_slice(il);
        let il_scalar: Scalar = <Scalar as Reduce<U256>>::reduce(il_uint);

        // Add scalars (this performs modular addition)
        let child_scalar = parent_scalar + il_scalar;

        // Convert scalar back to bytes
        let child_bytes: [u8; 32] = child_scalar.to_bytes().into();
        let child_private_key = BtcPrivateKey::from_bytes(&child_bytes)?;

        // Compute parent fingerprint (first 4 bytes of hash160 of parent public key)
        let parent_pubkey = self.private_key.public_key();
        let parent_hash = parent_pubkey.hash160();
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&parent_hash[..4]);

        // Child chain code
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);

        Ok(Self {
            private_key: child_private_key,
            chain_code,
            depth: self.depth + 1,
            parent_fingerprint,
            child_index: index,
            network: self.network,
        })
    }

    /// Derive from a path string (e.g., "m/44'/0'/0'/0/0").
    #[cfg(feature = "alloc")]
    pub fn derive_path(&self, path: &str) -> Result<Self> {
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

            let (index_str, hardened) = if component.ends_with('\'') || component.ends_with('h') {
                (&component[..component.len() - 1], true)
            } else {
                (component, false)
            };

            let index: u32 = index_str
                .parse()
                .map_err(|_| Error::InvalidDerivationPath)?;

            let child_index = if hardened {
                ChildIndex::Hardened(index)
            } else {
                ChildIndex::Normal(index)
            };

            current = current.derive_child(child_index)?;
        }

        Ok(current)
    }

    /// Get the underlying private key.
    pub fn private_key(&self) -> &BtcPrivateKey {
        &self.private_key
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> BtcPublicKey {
        self.private_key.public_key()
    }

    /// Get the chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the depth.
    pub const fn depth(&self) -> u8 {
        self.depth
    }

    /// Get the parent fingerprint.
    pub const fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    /// Get the child index.
    pub const fn child_index(&self) -> ChildIndex {
        self.child_index
    }

    /// Get the network.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Derive an address.
    pub fn address(&self, format: AddressFormat) -> Result<BtcAddress> {
        self.private_key.address(self.network, format)
    }

    /// Serialize to xprv format (Base58Check).
    #[cfg(feature = "alloc")]
    pub fn to_xprv(&self) -> String {
        let mut data = Vec::with_capacity(78);

        // Version bytes (4 bytes)
        let version = match self.network {
            Network::Mainnet => [0x04, 0x88, 0xAD, 0xE4], // xprv
            Network::Testnet => [0x04, 0x35, 0x83, 0x94], // tprv
        };
        data.extend_from_slice(&version);

        // Depth (1 byte)
        data.push(self.depth);

        // Parent fingerprint (4 bytes)
        data.extend_from_slice(&self.parent_fingerprint);

        // Child index (4 bytes, big-endian)
        data.extend_from_slice(&self.child_index.to_u32().to_be_bytes());

        // Chain code (32 bytes)
        data.extend_from_slice(&self.chain_code);

        // Private key (33 bytes: 0x00 + 32-byte key)
        data.push(0x00);
        data.extend_from_slice(&self.private_key.to_bytes());

        // Checksum (4 bytes)
        let checksum = kobe::hash::double_sha256(&data);
        data.extend_from_slice(&checksum[..4]);

        bs58::encode(data).into_string()
    }

    /// Parse from xprv format (Base58Check).
    #[cfg(feature = "alloc")]
    pub fn from_xprv(xprv: &str) -> Result<Self> {
        let decoded = bs58::decode(xprv)
            .into_vec()
            .map_err(|_| Error::InvalidEncoding)?;

        if decoded.len() != 82 {
            return Err(Error::InvalidLength {
                expected: 82,
                actual: decoded.len(),
            });
        }

        // Verify checksum
        let checksum = &decoded[78..];
        let computed = kobe::hash::double_sha256(&decoded[..78]);
        if checksum != &computed[..4] {
            return Err(Error::InvalidChecksum);
        }

        // Parse version to determine network
        let network = match &decoded[..4] {
            [0x04, 0x88, 0xAD, 0xE4] => Network::Mainnet, // xprv
            [0x04, 0x35, 0x83, 0x94] => Network::Testnet, // tprv
            _ => return Err(Error::msg("unknown extended key version")),
        };

        let depth = decoded[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&decoded[5..9]);

        let child_index = ChildIndex::from(u32::from_be_bytes([
            decoded[9],
            decoded[10],
            decoded[11],
            decoded[12],
        ]));

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&decoded[13..45]);

        // Private key (skip 0x00 prefix)
        if decoded[45] != 0x00 {
            return Err(Error::msg("invalid private key prefix"));
        }
        let private_key = BtcPrivateKey::from_bytes(&decoded[46..78])?;

        Ok(Self {
            private_key,
            chain_code,
            depth,
            parent_fingerprint,
            child_index,
            network,
        })
    }
}

impl core::fmt::Debug for ExtendedPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("depth", &self.depth)
            .field("child_index", &self.child_index)
            .field("network", &self.network)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 test vector 1
    const TEST_SEED_1: &[u8] = &hex_literal::hex!("000102030405060708090a0b0c0d0e0f");

    #[test]
    fn test_master_key_from_seed() {
        let xkey = ExtendedPrivateKey::from_seed(TEST_SEED_1, Network::Mainnet).unwrap();
        assert_eq!(xkey.depth(), 0);

        let xprv = xkey.to_xprv();
        assert!(xprv.starts_with("xprv"));
    }

    #[test]
    fn test_bip32_vector1_chain_m() {
        let xkey = ExtendedPrivateKey::from_seed(TEST_SEED_1, Network::Mainnet).unwrap();
        assert_eq!(
            xkey.to_xprv(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
    }

    #[test]
    fn test_bip32_vector1_chain_m_0h() {
        let master = ExtendedPrivateKey::from_seed(TEST_SEED_1, Network::Mainnet).unwrap();
        let child = master.derive_child(ChildIndex::Hardened(0)).unwrap();
        assert_eq!(
            child.to_xprv(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );
    }

    #[test]
    fn test_derive_path() {
        let master = ExtendedPrivateKey::from_seed(TEST_SEED_1, Network::Mainnet).unwrap();
        let derived = master.derive_path("m/0'").unwrap();
        assert_eq!(derived.depth(), 1);

        let derived2 = master.derive_path("m/0'/1").unwrap();
        assert_eq!(derived2.depth(), 2);
    }

    #[test]
    fn test_xprv_roundtrip() {
        let master = ExtendedPrivateKey::from_seed(TEST_SEED_1, Network::Mainnet).unwrap();
        let xprv = master.to_xprv();
        let recovered = ExtendedPrivateKey::from_xprv(&xprv).unwrap();
        assert_eq!(master.to_xprv(), recovered.to_xprv());
    }

    #[test]
    fn test_testnet_tprv() {
        let xkey = ExtendedPrivateKey::from_seed(TEST_SEED_1, Network::Testnet).unwrap();
        let tprv = xkey.to_xprv();
        assert!(tprv.starts_with("tprv"));
    }
}
