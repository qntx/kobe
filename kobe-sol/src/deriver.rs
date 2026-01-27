//! Solana address derivation from HD wallet.

use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::VerifyingKey;
use zeroize::Zeroizing;

use crate::Error;
use crate::slip10::DerivedKey;
use kobe_core::Wallet;

/// A derived Solana address with associated keys.
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// Derivation path used (e.g., `m/44'/501'/0'/0'`).
    pub path: String,
    /// Private key in hex format (zeroized on drop).
    pub private_key_hex: Zeroizing<String>,
    /// Public key in hex format.
    pub public_key_hex: String,
    /// Solana address (Base58 encoded public key).
    pub address: String,
}

#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Solana deriver from a wallet.
    #[inline]
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive a Solana address at the given account index.
    ///
    /// Uses path: m/44'/501'/account'/0'
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[inline]
    pub fn derive(&self, account: u32) -> Result<DerivedAddress, Error> {
        self.derive_with_change(account, 0)
    }

    /// Derive a Solana address with custom account and change index.
    ///
    /// Uses path: m/44'/501'/account'/change'
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    pub fn derive_with_change(&self, account: u32, change: u32) -> Result<DerivedAddress, Error> {
        let path = DerivedKey::format_path(account, change);
        self.derive_at_path(account, change).map(|mut addr| {
            addr.path = path;
            addr
        })
    }

    /// Internal derivation at specific account/change indices.
    fn derive_at_path(&self, account: u32, change: u32) -> Result<DerivedAddress, Error> {
        let derived = DerivedKey::derive_solana_path(self.wallet.seed(), account, change)?;
        let signing_key = derived.to_signing_key();
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let public_key_bytes = verifying_key.as_bytes();
        let address = bs58::encode(public_key_bytes).into_string();

        Ok(DerivedAddress {
            path: DerivedKey::format_path(account, change),
            private_key_hex: Zeroizing::new(hex::encode(derived.private_key.as_slice())),
            public_key_hex: hex::encode(public_key_bytes),
            address,
        })
    }

    /// Derive multiple addresses in sequence.
    ///
    /// # Arguments
    ///
    /// * `start_index` - Starting account index
    /// * `count` - Number of addresses to derive
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    pub fn derive_many(&self, start_index: u32, count: u32) -> Result<Vec<DerivedAddress>, Error> {
        (start_index..start_index + count)
            .map(|account| self.derive(account))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_derive_address() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let addr = deriver.derive(0).unwrap();

        // Solana addresses are 32-44 characters in Base58
        assert!(addr.address.len() >= 32 && addr.address.len() <= 44);
        assert_eq!(addr.path, "m/44'/501'/0'/0'");
    }

    #[test]
    fn test_derive_many() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let addresses = deriver.derive_many(0, 3).unwrap();

        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0].path, "m/44'/501'/0'/0'");
        assert_eq!(addresses[1].path, "m/44'/501'/1'/0'");
        assert_eq!(addresses[2].path, "m/44'/501'/2'/0'");

        // All addresses should be unique
        assert_ne!(addresses[0].address, addresses[1].address);
        assert_ne!(addresses[1].address, addresses[2].address);
    }

    #[test]
    fn test_deterministic_derivation() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);

        let addr1 = deriver.derive(0).unwrap();
        let addr2 = deriver.derive(0).unwrap();

        assert_eq!(addr1.address, addr2.address);
        assert_eq!(*addr1.private_key_hex, *addr2.private_key_hex);
    }
}
