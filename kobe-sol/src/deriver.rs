//! Solana address derivation from HD wallet.

use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::VerifyingKey;
use zeroize::Zeroizing;

use crate::Error;
use crate::derivation_style::DerivationStyle;
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

/// Solana address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe_core::Wallet`] and derives
/// Solana addresses following BIP44/SLIP-0010 standards.
///
/// # Example
///
/// ```
/// use kobe_core::Wallet;
/// use kobe_sol::Deriver;
///
/// let wallet = Wallet::generate(12, None).unwrap();
/// let deriver = Deriver::new(&wallet);
/// let addr = deriver.derive(0).unwrap();
/// println!("Address: {}", addr.address);
/// ```
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

    /// Derive a Solana address using the default Standard style.
    ///
    /// Uses path: `m/44'/501'/index'/0'` (Phantom, Backpack, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[inline]
    pub fn derive(&self, index: u32) -> Result<DerivedAddress, Error> {
        self.derive_with_style(DerivationStyle::Standard, index)
    }

    /// Derive a Solana address with a specific derivation style.
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[allow(deprecated)]
    pub fn derive_with_style(
        &self,
        style: DerivationStyle,
        index: u32,
    ) -> Result<DerivedAddress, Error> {
        let derived = match style {
            DerivationStyle::Standard => {
                DerivedKey::derive_standard_path(self.wallet.seed(), index)?
            }
            DerivationStyle::Trust => DerivedKey::derive_trust_path(self.wallet.seed(), index)?,
            DerivationStyle::LedgerLive => {
                DerivedKey::derive_ledger_live_path(self.wallet.seed(), index)?
            }
            DerivationStyle::Legacy => DerivedKey::derive_legacy_path(self.wallet.seed(), index)?,
        };

        let signing_key = derived.to_signing_key();
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let public_key_bytes = verifying_key.as_bytes();

        Ok(DerivedAddress {
            path: style.path(index),
            private_key_hex: Zeroizing::new(hex::encode(derived.private_key.as_slice())),
            public_key_hex: hex::encode(public_key_bytes),
            address: bs58::encode(public_key_bytes).into_string(),
        })
    }

    /// Derive multiple addresses using the default Standard style.
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    pub fn derive_many(&self, start_index: u32, count: u32) -> Result<Vec<DerivedAddress>, Error> {
        self.derive_many_with_style(DerivationStyle::Standard, start_index, count)
    }

    /// Derive multiple addresses with a specific derivation style.
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    pub fn derive_many_with_style(
        &self,
        style: DerivationStyle,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<DerivedAddress>, Error> {
        (start_index..start_index + count)
            .map(|account| self.derive_with_style(style, account))
            .collect()
    }
}

#[cfg(test)]
#[allow(deprecated)]
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

    #[test]
    fn test_derive_with_trust_style() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let addr = deriver
            .derive_with_style(DerivationStyle::Trust, 0)
            .unwrap();

        assert_eq!(addr.path, "m/44'/501'/0'");
        assert!(addr.address.len() >= 32 && addr.address.len() <= 44);
    }

    #[test]
    fn test_derive_with_ledger_live_style() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let addr = deriver
            .derive_with_style(DerivationStyle::LedgerLive, 0)
            .unwrap();

        assert_eq!(addr.path, "m/44'/501'/0'/0'/0'");
        assert!(addr.address.len() >= 32 && addr.address.len() <= 44);
    }

    #[test]
    fn test_different_styles_produce_different_addresses() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);

        let standard = deriver
            .derive_with_style(DerivationStyle::Standard, 0)
            .unwrap();
        let trust = deriver
            .derive_with_style(DerivationStyle::Trust, 0)
            .unwrap();
        let ledger_live = deriver
            .derive_with_style(DerivationStyle::LedgerLive, 0)
            .unwrap();
        let legacy = deriver
            .derive_with_style(DerivationStyle::Legacy, 0)
            .unwrap();

        // All styles should produce different addresses
        assert_ne!(standard.address, trust.address);
        assert_ne!(standard.address, ledger_live.address);
        assert_ne!(standard.address, legacy.address);
        assert_ne!(trust.address, ledger_live.address);
    }
}
