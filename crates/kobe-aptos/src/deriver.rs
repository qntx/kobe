//! Aptos address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String};

pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::DeriveError;

/// Ed25519 secret key size in bytes.
const ED25519_SECRET_SIZE: usize = 32;

/// Ed25519 single-signature scheme identifier used by Aptos.
const ED25519_SCHEME: u8 = 0x00;

/// Aptos address deriver from a unified wallet seed.
///
/// Derives Aptos addresses using SLIP-10 Ed25519 at path `m/44'/637'/{index}'/0'/0'`.
/// Address = `0x` + hex(SHA3-256(0x00 || pubkey)).
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Aptos deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Internal: derive at an arbitrary SLIP-10 path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let derived_key = self.wallet.derive_ed25519(path)?;
        let signing_key = derived_key.to_signing_key();
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32] = verifying_key.as_bytes();

        // Aptos authentication key = SHA3-256(pubkey || scheme_byte).
        // Scheme byte is appended AFTER the public key per
        // <https://aptos.dev/move-reference/mainnet/aptos-stdlib/ed25519>.
        let mut buf = [0u8; 33];
        buf[..32].copy_from_slice(pubkey_bytes);
        buf[32] = ED25519_SCHEME;
        let hash = Sha3_256::digest(buf);

        let mut sk_bytes = Zeroizing::new([0u8; ED25519_SECRET_SIZE]);
        sk_bytes.copy_from_slice(&signing_key.to_bytes());

        Ok(DerivedAccount::new(
            String::from(path),
            sk_bytes,
            pubkey_bytes.to_vec(),
            format!("0x{}", hex::encode(hash)),
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(&format!("m/44'/637'/{index}'/0'/0'"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    #[test]
    fn derive_starts_with_0x() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert!(derived.address().starts_with("0x"));
    }

    #[test]
    fn derive_address_length() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        // 0x + 64 hex chars = 66 total
        assert_eq!(derived.address().len(), 66);
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path(), "m/44'/637'/0'/0'/0'");
    }

    #[test]
    fn different_indices_differ() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        assert_ne!(
            d.derive(0).unwrap().address(),
            d.derive(1).unwrap().address()
        );
    }

    #[test]
    fn deterministic() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        assert_eq!(
            d.derive(0).unwrap().address(),
            d.derive(0).unwrap().address()
        );
    }

    /// Regression-lock the Aptos address derived from the canonical
    /// `abandon…about` mnemonic at path `m/44'/637'/0'/0'/0'`.
    ///
    /// Auth key follows the Aptos spec:
    /// `SHA3-256(pubkey || SIGNATURE_SCHEME_ID)` with `SIGNATURE_SCHEME_ID =
    /// 0x00` for Ed25519, per the `aptos-stdlib` Move source at
    /// <https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-stdlib/sources/cryptography/ed25519.move>.
    #[test]
    fn kat_aptos_index0() {
        let wallet = test_wallet();
        let a = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(
            a.address(),
            "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf"
        );
    }
}
