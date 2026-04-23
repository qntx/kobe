//! Sui address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet};
use zeroize::Zeroizing;

use crate::DeriveError;

/// Ed25519 signature scheme flag used by Sui.
const ED25519_FLAG: u8 = 0x00;

/// Sui address deriver from a unified wallet seed.
///
/// Derives Sui addresses using SLIP-10 Ed25519 at path `m/44'/784'/{index}'/0'/0'`.
/// Address = `0x` + hex(BLAKE2b-256(0x00 || pubkey)).
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Sui deriver from a wallet.
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

        let mut buf = Vec::with_capacity(33);
        buf.push(ED25519_FLAG);
        buf.extend_from_slice(pubkey_bytes);
        let hash = blake2b_256(&buf)?;

        let mut sk_bytes = Zeroizing::new([0u8; 32]);
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
        self.derive_at_path(&format!("m/44'/784'/{index}'/0'/0'"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
}

/// Compute BLAKE2b-256.
fn blake2b_256(data: &[u8]) -> Result<[u8; 32], DeriveError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| DeriveError::Hashing)?;
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|_| DeriveError::Hashing)?;
    Ok(out)
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
        assert_eq!(derived.address().len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path(), "m/44'/784'/0'/0'/0'");
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
    fn kat_sui_index0() {
        // Cross-verified with Python SLIP-10 + nacl + BLAKE2b-256(0x00||pubkey)
        let wallet = test_wallet();
        let a = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(
            a.address(),
            "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1"
        );
    }
}
