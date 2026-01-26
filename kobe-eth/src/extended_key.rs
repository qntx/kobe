//! BIP-32 Hierarchical Deterministic (HD) key derivation for Ethereum.
//!
//! Implements `kobe::ExtendedPrivateKey` trait for unified wallet interface.

use hmac::{Hmac, Mac};
use k256::elliptic_curve::ops::Reduce;
use k256::{Scalar, U256};
use sha2::Sha512;
use zeroize::Zeroize;

use kobe::{Error, PrivateKey as _, Result};

use crate::address::EthAddress;
use crate::private_key::EthPrivateKey;
use crate::public_key::EthPublicKey;

type HmacSha512 = Hmac<Sha512>;

/// BIP-32 Extended Private Key for Ethereum.
///
/// Provides hierarchical deterministic key derivation following the BIP-32 standard.
/// Keys are automatically zeroized on drop for security.
#[derive(Clone)]
pub struct EthExtendedPrivateKey {
    /// The underlying private key
    private_key: EthPrivateKey,
    /// Chain code for key derivation
    chain_code: [u8; 32],
    /// Depth in the derivation tree (0 for master)
    depth: u8,
    /// Parent key fingerprint (first 4 bytes of hash160 of parent public key)
    parent_fingerprint: [u8; 4],
    /// Child index that produced this key
    child_index: u32,
}

impl Zeroize for EthExtendedPrivateKey {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
        self.chain_code.zeroize();
        self.depth = 0;
        self.parent_fingerprint.zeroize();
    }
}

impl Drop for EthExtendedPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl kobe::ExtendedPrivateKey for EthExtendedPrivateKey {
    type PrivateKey = EthPrivateKey;

    fn from_seed(seed: &[u8]) -> Result<Self> {
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
        let private_key = EthPrivateKey::from_bytes(&result[..32])?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self {
            private_key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
        })
    }

    fn derive_child(&self, index: u32) -> Result<Self> {
        self.derive_child_internal(index, false)
    }

    fn derive_child_hardened(&self, index: u32) -> Result<Self> {
        self.derive_child_internal(index, true)
    }

    #[cfg(feature = "alloc")]
    fn derive_path(&self, path: &str) -> Result<Self> {
        self.derive_path_str(path)
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }

    fn chain_code(&self) -> [u8; 32] {
        self.chain_code
    }

    fn depth(&self) -> u8 {
        self.depth
    }
}

impl EthExtendedPrivateKey {
    /// Derive a child key at the given index.
    fn derive_child_internal(&self, index: u32, hardened: bool) -> Result<Self> {
        if self.depth == 255 {
            return Err(Error::MaxDepthExceeded);
        }

        let child_index = if hardened { index | 0x80000000 } else { index };

        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).map_err(|_| Error::CryptoError)?;

        if hardened {
            // Hardened derivation: HMAC-SHA512(Key = chainCode, Data = 0x00 || ser256(kpar) || ser32(i))
            mac.update(&[0u8]);
            mac.update(&kobe::PrivateKey::to_bytes(&self.private_key));
        } else {
            // Normal derivation: HMAC-SHA512(Key = chainCode, Data = serP(point(kpar)) || ser32(i))
            let pubkey = kobe::PrivateKey::public_key(&self.private_key);
            mac.update(&kobe::PublicKey::to_bytes(&pubkey));
        }

        mac.update(&child_index.to_be_bytes());
        let result = mac.finalize().into_bytes();

        // Parse IL as 256-bit number and add to parent key
        let il = &result[..32];
        let ir = &result[32..];

        // Create child key: child = parse256(IL) + parent (mod n)
        let parent_bytes = kobe::PrivateKey::to_bytes(&self.private_key);
        let parent_uint = U256::from_be_slice(&parent_bytes);
        let parent_scalar: Scalar = <Scalar as Reduce<U256>>::reduce(parent_uint);

        let il_uint = U256::from_be_slice(il);
        let il_scalar: Scalar = <Scalar as Reduce<U256>>::reduce(il_uint);

        // Add scalars (this performs modular addition)
        let child_scalar = parent_scalar + il_scalar;

        // Convert scalar back to bytes
        let child_bytes: [u8; 32] = child_scalar.to_bytes().into();
        let child_private_key = EthPrivateKey::from_bytes(&child_bytes)?;

        // Compute parent fingerprint (first 4 bytes of hash160 of parent public key)
        let parent_pubkey = kobe::PrivateKey::public_key(&self.private_key);
        let parent_hash = kobe::hash::hash160(&kobe::PublicKey::to_bytes(&parent_pubkey));
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
            child_index,
        })
    }

    /// Derives a key from a BIP-32 path string.
    ///
    /// Standard Ethereum path is `m/44'/60'/0'/0/0`.
    ///
    /// # Example
    /// ```ignore
    /// let wallet = xprv.derive_path_str("m/44'/60'/0'/0/0")?;
    /// let addr = wallet.address();
    /// ```
    #[cfg(feature = "alloc")]
    pub fn derive_path_str(&self, path: &str) -> Result<Self> {
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

            current = current.derive_child_internal(index, hardened)?;
        }

        Ok(current)
    }

    /// Get a reference to the underlying private key.
    #[inline]
    pub fn private_key_ref(&self) -> &EthPrivateKey {
        &self.private_key
    }

    /// Get the corresponding public key.
    #[inline]
    #[must_use]
    pub fn public_key(&self) -> EthPublicKey {
        kobe::PrivateKey::public_key(&self.private_key)
    }

    /// Get the corresponding address.
    #[inline]
    #[must_use]
    pub fn address(&self) -> EthAddress {
        self.private_key.address()
    }

    /// Get a reference to the chain code.
    #[inline]
    pub fn chain_code_ref(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the depth in the derivation tree.
    #[inline]
    #[must_use]
    pub const fn depth_value(&self) -> u8 {
        self.depth
    }

    /// Get the parent fingerprint.
    #[inline]
    #[must_use]
    pub const fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    /// Get the child index.
    #[inline]
    #[must_use]
    pub const fn child_index(&self) -> u32 {
        self.child_index
    }
}

impl core::fmt::Debug for EthExtendedPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EthExtendedPrivateKey")
            .field("depth", &self.depth)
            .field("child_index", &self.child_index)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kobe::ExtendedPrivateKey as _;

    // BIP-32 test vector 1
    const TEST_SEED_1: &[u8] = &hex_literal::hex!("000102030405060708090a0b0c0d0e0f");

    #[test]
    fn test_master_key_from_seed() {
        let xkey = EthExtendedPrivateKey::from_seed(TEST_SEED_1).unwrap();
        assert_eq!(xkey.depth(), 0);
    }

    #[test]
    fn test_derive_path() {
        let master = EthExtendedPrivateKey::from_seed(TEST_SEED_1).unwrap();
        // Standard Ethereum derivation path
        let derived = master.derive_path_str("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(derived.depth(), 5);

        // Verify address derivation works
        let _addr = derived.address();
    }

    #[test]
    fn test_hardened_derivation() {
        let master = EthExtendedPrivateKey::from_seed(TEST_SEED_1).unwrap();
        let child = master.derive_child_hardened(44).unwrap();
        assert_eq!(child.depth(), 1);
    }
}
