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
    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    /// Known-answer test at Sui's default `m/44'/784'/{i}'/0'/0'` path.
    ///
    /// Cross-verified with an independent Node.js pipeline (`bip39 →
    /// ed25519-hd-key SLIP-10 → tweetnacl key pair →
    /// blake2b-256(0x00 || pubkey)`) using `@noble/hashes`, per the Sui
    /// authentication spec at
    /// <https://docs.sui.io/guides/developer/transactions/transaction-auth/auth-overview>.
    #[test]
    fn kat_sui_abandon_index0() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/784'/0'/0'/0'");
        assert_eq!(
            a.address(),
            "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1"
        );
        assert_eq!(
            a.private_key_hex().as_str(),
            "8869cb07178bf67e08d7c4abdf45487dbf379c9a452fcec2836854bf4a3d29b0"
        );
    }

    #[test]
    fn kat_sui_abandon_index1() {
        let a = Deriver::new(&test_wallet()).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/784'/1'/0'/0'");
        assert_eq!(
            a.address(),
            "0x082d099250999ab8450a9ef3a962edf9e2449e1045be32ba5a0f2c6117ff7167"
        );
        assert_eq!(
            a.private_key_hex().as_str(),
            "72613d6091bf9d0b2a9b28e8a18b1de1d527fa60ab2656c5905e92431c98b918"
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

    #[test]
    fn passphrase_changes_derivation() {
        let w = Wallet::from_mnemonic(TEST_MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            Deriver::new(&test_wallet()).derive(0).unwrap().address(),
            Deriver::new(&w).derive(0).unwrap().address(),
        );
    }
}
