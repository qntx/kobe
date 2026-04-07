//! SLIP-0010 Ed25519 key derivation.
//!
//! Implements the SLIP-0010 standard for deriving Ed25519 keys from a BIP-39 seed.
//! Used by Solana, Sui, TON, and other Ed25519-based chains.
//!
//! Reference: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>

use alloc::format;

use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::DeriveError;

/// HMAC-SHA512 type alias.
type HmacSha512 = Hmac<Sha512>;

/// Curve identifier for Ed25519 master key derivation.
const ED25519_CURVE: &[u8] = b"ed25519 seed";

/// SLIP-0010 derived Ed25519 key pair.
///
/// Contains a 32-byte private key and chain code. All sensitive fields
/// are wrapped in [`Zeroizing`] for automatic secure cleanup on drop.
#[non_exhaustive]
pub struct DerivedKey {
    /// 32-byte Ed25519 private key.
    pub private_key: Zeroizing<[u8; 32]>,
    /// 32-byte chain code for further derivation.
    pub chain_code: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let pk = self.to_signing_key().verifying_key();
        f.debug_struct("DerivedKey")
            .field("public_key", &hex::encode(pk.as_bytes()))
            .finish_non_exhaustive()
    }
}

impl DerivedKey {
    /// Derive the master key from a BIP-39 seed using SLIP-0010.
    ///
    /// # Errors
    ///
    /// Returns an error if the HMAC key is invalid (should not happen in practice).
    pub fn from_seed(seed: &[u8]) -> Result<Self, DeriveError> {
        let mut mac = HmacSha512::new_from_slice(ED25519_CURVE)
            .map_err(|_| DeriveError::Slip10InvalidSeed)?;
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let (pk_bytes, cc_bytes) = result.split_at(32);
        let mut private_key = Zeroizing::new([0u8; 32]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        private_key.copy_from_slice(pk_bytes);
        chain_code.copy_from_slice(cc_bytes);

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
    pub fn derive_hardened(&self, index: u32) -> Result<Self, DeriveError> {
        let hardened_index = index | 0x8000_0000;

        let mut mac = HmacSha512::new_from_slice(&*self.chain_code)
            .map_err(|_| DeriveError::Slip10InvalidSeed)?;
        mac.update(&[0x00]);
        mac.update(&*self.private_key);
        mac.update(&hardened_index.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let (pk_bytes, cc_bytes) = result.split_at(32);
        let mut private_key = Zeroizing::new([0u8; 32]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        private_key.copy_from_slice(pk_bytes);
        chain_code.copy_from_slice(cc_bytes);

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
    pub fn derive_path(seed: &[u8], path: &str) -> Result<Self, DeriveError> {
        let trimmed = path.trim();
        let remainder = if trimmed == "m" {
            ""
        } else if let Some(rest) = trimmed.strip_prefix("m/") {
            rest
        } else {
            return Err(DeriveError::Slip10InvalidPath(
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
fn parse_path_component(component: &str) -> Result<u32, DeriveError> {
    let stripped = component.trim_end_matches('\'').trim_end_matches('h');
    stripped
        .parse::<u32>()
        .map_err(|_| DeriveError::Slip10InvalidPath(format!("invalid path component: {component}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // SLIP-0010 Test Vector 1 for Ed25519
    // Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
    const TV1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn slip10_vector1_chain_m() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let master = DerivedKey::from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(*master.private_key),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(*master.chain_code),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
    }

    #[test]
    fn slip10_vector1_chain_m_0h() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let derived = DerivedKey::derive_path(&seed, "m/0'").unwrap();
        assert_eq!(
            hex::encode(*derived.private_key),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex::encode(*derived.chain_code),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
        );
    }

    #[test]
    fn slip10_vector1_chain_m_0h_1h() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let derived = DerivedKey::derive_path(&seed, "m/0'/1'").unwrap();
        assert_eq!(
            hex::encode(*derived.private_key),
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"
        );
        assert_eq!(
            hex::encode(*derived.chain_code),
            "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"
        );
    }

    #[test]
    fn slip10_vector1_chain_m_0h_1h_2h() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let derived = DerivedKey::derive_path(&seed, "m/0'/1'/2'").unwrap();
        assert_eq!(
            hex::encode(*derived.private_key),
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"
        );
        assert_eq!(
            hex::encode(*derived.chain_code),
            "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c"
        );
    }

    #[test]
    fn slip10_vector1_chain_m_0h_1h_2h_2h() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let derived = DerivedKey::derive_path(&seed, "m/0'/1'/2'/2'").unwrap();
        assert_eq!(
            hex::encode(*derived.private_key),
            "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"
        );
        assert_eq!(
            hex::encode(*derived.chain_code),
            "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc"
        );
    }

    #[test]
    fn slip10_vector1_chain_m_0h_1h_2h_2h_1000000000h() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let derived = DerivedKey::derive_path(&seed, "m/0'/1'/2'/2'/1000000000'").unwrap();
        assert_eq!(
            hex::encode(*derived.private_key),
            "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
        );
        assert_eq!(
            hex::encode(*derived.chain_code),
            "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"
        );
    }

    // SLIP-0010 Test Vector 2 for Ed25519
    const TV2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

    #[test]
    fn slip10_vector2_chain_m() {
        let seed = hex::decode(TV2_SEED).unwrap();
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
    fn slip10_vector2_chain_m_0h() {
        let seed = hex::decode(TV2_SEED).unwrap();
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
    fn master_only_path() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let m = DerivedKey::from_seed(&seed).unwrap();
        let m2 = DerivedKey::derive_path(&seed, "m").unwrap();
        assert_eq!(*m.private_key, *m2.private_key);
        assert_eq!(*m.chain_code, *m2.chain_code);
    }

    #[test]
    fn h_suffix_accepted() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let a = DerivedKey::derive_path(&seed, "m/0'").unwrap();
        let b = DerivedKey::derive_path(&seed, "m/0h").unwrap();
        assert_eq!(*a.private_key, *b.private_key);
    }

    #[test]
    fn different_indices_produce_different_keys() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let k0 = DerivedKey::derive_path(&seed, "m/44'/501'/0'").unwrap();
        let k1 = DerivedKey::derive_path(&seed, "m/44'/501'/1'").unwrap();
        assert_ne!(*k0.private_key, *k1.private_key);
    }

    #[test]
    fn invalid_path_rejected() {
        let seed = hex::decode(TV1_SEED).unwrap();
        assert!(DerivedKey::derive_path(&seed, "bad/path").is_err());
        assert!(DerivedKey::derive_path(&seed, "m/abc").is_err());
    }

    #[test]
    fn signing_key_roundtrip() {
        let seed = hex::decode(TV1_SEED).unwrap();
        let derived = DerivedKey::from_seed(&seed).unwrap();
        let sk = derived.to_signing_key();
        assert_eq!(sk.to_bytes(), *derived.private_key);
    }
}
