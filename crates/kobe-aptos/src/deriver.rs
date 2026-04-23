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
    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    /// Known-answer test at Aptos's default `m/44'/637'/{i}'/0'/0'` path.
    ///
    /// Cross-verified with an independent Node.js pipeline (`bip39 →
    /// ed25519-hd-key SLIP-10 → tweetnacl key pair →
    /// sha3-256(pubkey || 0x00)`) using `@noble/hashes`. Aptos's
    /// authentication-key spec pushes the scheme byte *after* the public
    /// key, per the `aptos-stdlib` Move source at
    /// <https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-stdlib/sources/cryptography/ed25519.move>.
    #[test]
    fn kat_aptos_abandon_index0() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/637'/0'/0'/0'");
        assert_eq!(
            a.address(),
            "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf"
        );
        assert_eq!(
            a.private_key_hex().as_str(),
            "cc92c0eaf80206d817f150e21917f797e49cf644a33ac514de3c316baa2f1bf5"
        );
    }

    #[test]
    fn kat_aptos_abandon_index1() {
        let a = Deriver::new(&test_wallet()).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/637'/1'/0'/0'");
        assert_eq!(
            a.address(),
            "0xf867372dfec13fb6c0740d4b574363685e10e6f243e9554ffa8f6e698e940efa"
        );
        assert_eq!(
            a.private_key_hex().as_str(),
            "4c6f5a6b687631dd52f32c97457e895fb57947b9b827c6697c11cd7b2a075c5b"
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
