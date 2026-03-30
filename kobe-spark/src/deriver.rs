//! Spark address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::format;

pub use kobe_core::DerivedAccount;
use kobe_core::{Derive, Wallet};

use crate::Error;

/// Spark address deriver from a unified wallet seed.
///
/// Derives Spark addresses using BIP-84 path `m/84'/0'/0'/0/{index}`
/// (same as Bitcoin, since Spark is a Bitcoin L2).
/// Address format: `spark:<compressed_pubkey_hex>`.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Spark deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Internal: derive at an arbitrary BIP-32 path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        let key = kobe_core::bip32::DerivedSecp256k1Key::derive(self.wallet.seed(), path)?;
        let pubkey_hex = key.compressed_pubkey_hex();

        Ok(DerivedAccount::new(
            path.to_string(),
            key.private_key_hex(),
            pubkey_hex.clone(),
            format!("spark:{pubkey_hex}"),
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = Error;

    fn derive(&self, index: u32) -> Result<DerivedAccount, Error> {
        self.derive_at_path(&format!("m/84'/0'/0'/0/{index}"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        self.derive_at_path(path)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    #[test]
    fn derive_starts_with_spark() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert!(derived.address.starts_with("spark:"));
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path, "m/84'/0'/0'/0/0");
    }

    #[test]
    fn deterministic() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_eq!(a1.address, a2.address);
    }

    #[test]
    fn different_indices_differ() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        assert_ne!(d.derive(0).unwrap().address, d.derive(1).unwrap().address);
    }

    #[test]
    fn uses_same_path_as_bitcoin_bip84() {
        let wallet = test_wallet();
        let spark = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(spark.path, "m/84'/0'/0'/0/0");
    }

    #[test]
    fn kat_spark_index0() {
        // Cross-verified with Python coincurve compressed pubkey at BIP-84 path
        let wallet = test_wallet();
        let a = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(
            a.address,
            "spark:0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        );
    }
}
