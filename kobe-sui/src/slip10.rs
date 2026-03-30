//! SLIP-0010 Ed25519 key derivation for Sui.

use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::Error;

/// HMAC-SHA512 type alias.
type HmacSha512 = Hmac<Sha512>;

/// Curve identifier for Ed25519 master key derivation.
const ED25519_CURVE: &[u8] = b"ed25519 seed";

/// SLIP-10 derived key pair.
pub struct DerivedKey {
    /// 32-byte private key.
    pub private_key: Zeroizing<[u8; 32]>,
    /// 32-byte chain code.
    pub chain_code: Zeroizing<[u8; 32]>,
}

impl DerivedKey {
    /// Derive master key from seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let mut mac =
            HmacSha512::new_from_slice(ED25519_CURVE).map_err(|_| Error::InvalidSeedLength)?;
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

    /// Derive child key at hardened index.
    pub fn derive_hardened(&self, index: u32) -> Result<Self, Error> {
        let hardened_index = index | 0x8000_0000;
        let mut mac =
            HmacSha512::new_from_slice(&*self.chain_code).map_err(|_| Error::InvalidSeedLength)?;
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

    /// Derive key at a custom SLIP-10 path (all components hardened).
    pub fn derive_path(seed: &[u8], path: &str) -> Result<Self, Error> {
        let trimmed = path.trim();
        let remainder = if trimmed == "m" {
            ""
        } else if let Some(rest) = trimmed.strip_prefix("m/") {
            rest
        } else {
            return Err(Error::Derivation(
                "path must start with 'm/' or be 'm'".into(),
            ));
        };

        let mut current = Self::from_seed(seed)?;
        for component in remainder.split('/').filter(|s| !s.is_empty()) {
            let stripped = component.trim_end_matches('\'').trim_end_matches('h');
            let index: u32 = stripped.parse().map_err(|_| {
                Error::Derivation(alloc::format!("invalid path component: {component}"))
            })?;
            current = current.derive_hardened(index)?;
        }
        Ok(current)
    }

    /// Convert to Ed25519 signing key.
    pub fn to_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.private_key)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn master_key_from_seed() {
        let seed = [0u8; 64];
        let master = DerivedKey::from_seed(&seed).unwrap();
        assert_eq!(master.private_key.len(), 32);
    }

    #[test]
    fn sui_path_derivation() {
        let seed = [0u8; 64];
        let derived = DerivedKey::derive_path(&seed, "m/44'/784'/0'/0'/0'").unwrap();
        assert_eq!(derived.private_key.len(), 32);
    }

    #[test]
    fn different_indices_produce_different_keys() {
        let seed = [1u8; 64];
        let k0 = DerivedKey::derive_path(&seed, "m/44'/784'/0'/0'/0'").unwrap();
        let k1 = DerivedKey::derive_path(&seed, "m/44'/784'/1'/0'/0'").unwrap();
        assert_ne!(*k0.private_key, *k1.private_key);
    }
}
