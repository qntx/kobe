//! SLIP-0010 Ed25519 key derivation.
//!
//! Implements the SLIP-0010 standard for deriving Ed25519 keys from a BIP-39 seed.
//! Used by Solana, Sui, TON, and other Ed25519-based chains.
//!
//! Reference: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>

use alloc::format;

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::Error;

/// HMAC-SHA512 type alias.
type HmacSha512 = Hmac<Sha512>;

/// Curve identifier for Ed25519 master key derivation.
const ED25519_CURVE: &[u8] = b"ed25519 seed";

/// SLIP-0010 derived Ed25519 key pair.
///
/// Contains a 32-byte private key and chain code. All sensitive fields
/// are wrapped in [`Zeroizing`] for automatic secure cleanup on drop.
#[derive(Debug)]
#[non_exhaustive]
pub struct DerivedKey {
    /// 32-byte Ed25519 private key.
    pub private_key: Zeroizing<[u8; 32]>,
    /// 32-byte chain code for further derivation.
    pub chain_code: Zeroizing<[u8; 32]>,
}

impl DerivedKey {
    /// Derive the master key from a BIP-39 seed using SLIP-0010.
    ///
    /// # Errors
    ///
    /// Returns an error if the HMAC key is invalid (should not happen in practice).
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let mut mac =
            HmacSha512::new_from_slice(ED25519_CURVE).map_err(|_| Error::Slip10InvalidSeed)?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut private_key = Zeroizing::new([0u8; 32]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        private_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self {
            private_key,
            chain_code,
        })
    }

    /// Derive a child key at a hardened index.
    ///
    /// SLIP-0010 only supports hardened derivation for Ed25519.
    /// The hardened flag (`0x8000_0000`) is applied automatically.
    ///
    /// # Errors
    ///
    /// Returns an error if the HMAC key is invalid.
    pub fn derive_hardened(&self, index: u32) -> Result<Self, Error> {
        let hardened_index = index | 0x8000_0000;

        let mut mac =
            HmacSha512::new_from_slice(&*self.chain_code).map_err(|_| Error::Slip10InvalidSeed)?;
        mac.update(&[0x00]);
        mac.update(&*self.private_key);
        mac.update(&hardened_index.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let mut private_key = Zeroizing::new([0u8; 32]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        private_key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        Ok(Self {
            private_key,
            chain_code,
        })
    }

    /// Derive a key at an arbitrary SLIP-0010 path.
    ///
    /// Path format: `m/44'/501'/0'/0'` — all components are treated as
    /// hardened (Ed25519 requirement). Trailing `'` or `h` markers are optional.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is malformed or derivation fails.
    pub fn derive_path(seed: &[u8], path: &str) -> Result<Self, Error> {
        let trimmed = path.trim();
        let remainder = if trimmed == "m" {
            ""
        } else if let Some(rest) = trimmed.strip_prefix("m/") {
            rest
        } else {
            return Err(Error::Slip10InvalidPath(
                "path must start with 'm/' or be exactly 'm'".into(),
            ));
        };

        let mut current = Self::from_seed(seed)?;
        for component in remainder.split('/').filter(|s| !s.is_empty()) {
            let index = parse_path_component(component)?;
            current = current.derive_hardened(index)?;
        }
        Ok(current)
    }

    /// Convert the derived private key to an Ed25519 [`SigningKey`].
    #[must_use]
    pub fn to_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.private_key)
    }
}

/// Parse a single path component like `"44'"` or `"501h"` into a u32 index.
fn parse_path_component(component: &str) -> Result<u32, Error> {
    let stripped = component.trim_end_matches('\'').trim_end_matches('h');
    stripped
        .parse::<u32>()
        .map_err(|_| Error::Slip10InvalidPath(format!("invalid path component: {component}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn master_key_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = DerivedKey::from_seed(&seed).unwrap();
        assert_eq!(master.private_key.len(), 32);
        assert_eq!(master.chain_code.len(), 32);
    }

    #[test]
    fn slip10_test_vector2_ed25519_master() {
        // SLIP-0010 Test vector 2 for ed25519 — Chain m
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let master = DerivedKey::from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(*master.private_key),
            "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"
        );
        assert_eq!(
            hex::encode(*master.chain_code),
            "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b"
        );
    }

    #[test]
    fn slip10_test_vector2_ed25519_chain_m_0h() {
        // SLIP-0010 Test vector 2 for ed25519 — Chain m/0H
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let derived = DerivedKey::derive_path(&seed, "m/0'").unwrap();
        assert_eq!(
            hex::encode(*derived.private_key),
            "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"
        );
        assert_eq!(
            hex::encode(*derived.chain_code),
            "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d"
        );
    }

    #[test]
    fn standard_solana_path() {
        let seed = [0u8; 64];
        let derived = DerivedKey::derive_path(&seed, "m/44'/501'/0'/0'").unwrap();
        assert_eq!(derived.private_key.len(), 32);
    }

    #[test]
    fn sui_path() {
        let seed = [0u8; 64];
        let derived = DerivedKey::derive_path(&seed, "m/44'/784'/0'/0'/0'").unwrap();
        assert_eq!(derived.private_key.len(), 32);
    }

    #[test]
    fn ton_path() {
        let seed = [0u8; 64];
        let derived = DerivedKey::derive_path(&seed, "m/44'/607'/0'").unwrap();
        assert_eq!(derived.private_key.len(), 32);
    }

    #[test]
    fn master_only_path() {
        let seed = [0u8; 64];
        let m = DerivedKey::from_seed(&seed).unwrap();
        let m2 = DerivedKey::derive_path(&seed, "m").unwrap();
        assert_eq!(*m.private_key, *m2.private_key);
    }

    #[test]
    fn different_indices_produce_different_keys() {
        let seed = [1u8; 64];
        let k0 = DerivedKey::derive_path(&seed, "m/44'/501'/0'").unwrap();
        let k1 = DerivedKey::derive_path(&seed, "m/44'/501'/1'").unwrap();
        assert_ne!(*k0.private_key, *k1.private_key);
    }

    #[test]
    fn invalid_path_rejected() {
        let seed = [0u8; 64];
        assert!(DerivedKey::derive_path(&seed, "bad/path").is_err());
        assert!(DerivedKey::derive_path(&seed, "m/abc").is_err());
    }
}
