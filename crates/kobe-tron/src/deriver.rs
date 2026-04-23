//! Tron address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec};

use kobe_primitives::{Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet};
use sha3::{Digest, Keccak256};

/// Tron address deriver from a unified wallet seed.
///
/// Derives Tron addresses using BIP-44 path `m/44'/195'/0'/0/{index}`.
/// Tron addresses are base58check-encoded with a 0x41 mainnet prefix.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Tron deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive at an arbitrary BIP-32 path.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_at(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
        let uncompressed = key.uncompressed_pubkey();

        let hash = Keccak256::digest(&uncompressed[1..]);
        let (_, addr_bytes) = hash.split_at(12);
        let mut prefixed = vec![0x41u8];
        prefixed.extend_from_slice(addr_bytes);
        let address = bs58::encode(&prefixed).with_check().into_string();

        Ok(DerivedAccount::new(
            String::from(path),
            key.private_key_bytes(),
            DerivedPublicKey::Secp256k1Uncompressed(uncompressed),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Account = DerivedAccount;
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(&format!("m/44'/195'/0'/0/{index}"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(path)
    }
}

#[cfg(test)]
mod tests {
    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    /// Known-answer test at BIP-44 path `m/44'/195'/0'/0/{i}`.
    ///
    /// Cross-verified against an independent Node.js pipeline (`bip39 →
    /// bip32 → secp256k1 → uncompressed_pubkey[1..] → keccak256[12..32]
    /// → prefix 0x41 → base58check`) using `bip39`, `bip32`,
    /// `tiny-secp256k1`, `@cosmjs/crypto` and `bs58check`, per the Tron
    /// address spec at
    /// <https://developers.tron.network/docs/account#account-address>.
    #[test]
    fn kat_tron_abandon_index0() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/195'/0'/0/0");
        assert_eq!(a.address(), "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
        assert_eq!(
            a.private_key_hex().as_str(),
            "b5a4cea271ff424d7c31dc12a3e43e401df7a40d7412a15750f3f0b6b5449a28"
        );
    }

    #[test]
    fn kat_tron_abandon_index1() {
        let a = Deriver::new(&test_wallet()).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/195'/0'/0/1");
        assert_eq!(a.address(), "TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK");
        assert_eq!(
            a.private_key_hex().as_str(),
            "edb728e259afca2ddcc428459e7681b8414668649aedbc8d25c0872da219b2e6"
        );
    }

    /// `derive_many` must agree with scalar `derive` for every index.
    #[test]
    fn derive_many_matches_individual() {
        let w = test_wallet();
        let d = Deriver::new(&w);
        let batch = d.derive_many(0, 3).unwrap();
        let single: Vec<_> = (0..3).map(|i| d.derive(i).unwrap()).collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
        }
    }

    /// A non-empty BIP-39 passphrase must produce a completely different
    /// derivation tree.
    #[test]
    fn passphrase_changes_derivation() {
        let w = Wallet::from_mnemonic(TEST_MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            Deriver::new(&test_wallet()).derive(0).unwrap().address(),
            Deriver::new(&w).derive(0).unwrap().address(),
        );
    }
}
