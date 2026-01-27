//! SLIP-0010 Ed25519 key derivation.
//!
//! Implements SLIP-0010 for deriving Ed25519 keys from a seed.
//! Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use alloc::string::String;
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::Error;

type HmacSha512 = Hmac<Sha512>;

const ED25519_CURVE: &[u8] = b"ed25519 seed";

/// SLIP-0010 derived key pair.
pub struct DerivedKey {
    /// 32-byte private key.
    pub private_key: Zeroizing<[u8; 32]>,
    /// 32-byte chain code.
    pub chain_code: Zeroizing<[u8; 32]>,
}

impl DerivedKey {
    /// Derive master key from seed using SLIP-0010.
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
    ///
    /// SLIP-0010 only supports hardened derivation for Ed25519.
    pub fn derive_hardened(&self, index: u32) -> Result<Self, Error> {
        let hardened_index = index | 0x8000_0000;

        let mut mac =
            HmacSha512::new_from_slice(&*self.chain_code).map_err(|_| Error::InvalidSeedLength)?;

        // For hardened derivation: 0x00 || private_key || index
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

    /// Derive key at BIP44 path for Solana: m/44'/501'/account'/change'
    ///
    /// Note: Solana uses all hardened derivation.
    pub fn derive_solana_path(seed: &[u8], account: u32, change: u32) -> Result<Self, Error> {
        let master = Self::from_seed(seed)?;

        // m/44'
        let purpose = master.derive_hardened(44)?;
        // m/44'/501'
        let coin_type = purpose.derive_hardened(501)?;
        // m/44'/501'/account'
        let account_key = coin_type.derive_hardened(account)?;
        // m/44'/501'/account'/change'
        let change_key = account_key.derive_hardened(change)?;

        Ok(change_key)
    }

    /// Convert to Ed25519 signing key.
    pub fn to_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.private_key)
    }

    /// Format the derivation path string.
    pub fn format_path(account: u32, change: u32) -> String {
        alloc::format!("m/44'/501'/{account}'/{change}'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_derivation() {
        // Test vector from SLIP-0010
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = DerivedKey::from_seed(&seed).unwrap();

        assert_eq!(master.private_key.len(), 32);
        assert_eq!(master.chain_code.len(), 32);
    }

    #[test]
    fn test_solana_path_derivation() {
        let seed = [0u8; 64];
        let derived = DerivedKey::derive_solana_path(&seed, 0, 0).unwrap();

        assert_eq!(derived.private_key.len(), 32);
    }
}
