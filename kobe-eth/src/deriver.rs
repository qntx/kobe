//! Ethereum address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use bip32::{DerivationPath, XPrv};
use k256::ecdsa::SigningKey;
use kobe::Wallet;
use zeroize::Zeroizing;

use crate::Error;
use crate::address::{public_key_to_address, to_checksum_address};
use crate::derivation_style::DerivationStyle;

/// Ethereum address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe::Wallet`] and derives
/// Ethereum addresses following BIP32/44 standards.
///
/// # Example
///
/// ```
/// use kobe::Wallet;
/// use kobe_eth::Deriver;
///
/// let wallet = Wallet::generate(12, None).unwrap();
/// let deriver = Deriver::new(&wallet);
/// let addr = deriver.derive(0, false, 0).unwrap();
/// println!("Address: {}", addr.address);
/// ```
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

/// A derived Ethereum address with associated keys.
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// Derivation path used (e.g., `m/44'/60'/0'/0/0`).
    pub path: String,
    /// Private key in hex format without 0x prefix (zeroized on drop).
    pub private_key_hex: Zeroizing<String>,
    /// Public key in uncompressed hex format.
    pub public_key_hex: String,
    /// Checksummed Ethereum address (EIP-55)..
    pub address: String,
}

impl<'a> Deriver<'a> {
    /// Create a new Ethereum deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive an address using BIP44 standard path.
    ///
    /// Path format: `m/44'/60'/account'/change/address_index`
    ///
    /// # Arguments
    ///
    /// * `account` - Account index (usually 0)
    /// * `change` - Whether this is a change address (usually false for Ethereum)
    /// * `address_index` - Address index within the account
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[inline]
    pub fn derive(
        &self,
        account: u32,
        change: bool,
        address_index: u32,
    ) -> Result<DerivedAddress, Error> {
        let change_val = i32::from(change);
        let path = format!("m/44'/60'/{account}'/{change_val}/{address_index}");
        self.derive_at_path(&path)
    }

    /// Derive an address at a custom derivation path.
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    pub fn derive_at_path(&self, path: &str) -> Result<DerivedAddress, Error> {
        let private_key = self.derive_key(path)?;

        let public_key = private_key.verifying_key();
        let public_key_bytes = public_key.to_encoded_point(false);
        let address = public_key_to_address(public_key_bytes.as_bytes());

        Ok(DerivedAddress {
            path: path.to_string(),
            private_key_hex: Zeroizing::new(hex::encode(private_key.to_bytes())),
            public_key_hex: hex::encode(public_key_bytes.as_bytes()),
            address: to_checksum_address(&address),
        })
    }

    /// Derive multiple addresses in sequence.
    ///
    /// # Arguments
    ///
    /// * `account` - Account index (usually 0)
    /// * `change` - Whether these are change addresses
    /// * `start_index` - Starting address index
    /// * `count` - Number of addresses to derive
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    pub fn derive_many(
        &self,
        account: u32,
        change: bool,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<DerivedAddress>, Error> {
        (start_index..start_index + count)
            .map(|index| self.derive(account, change, index))
            .collect()
    }

    /// Derive an address using a specific wallet derivation style.
    ///
    /// This method supports different hardware/software wallet path formats:
    /// - **Standard** (MetaMask/Trezor): `m/44'/60'/0'/0/{index}`
    /// - **Ledger Live**: `m/44'/60'/{index}'/0/0`
    /// - **Ledger Legacy**: `m/44'/60'/0'/{index}`
    ///
    /// # Arguments
    ///
    /// * `style` - The derivation style to use
    /// * `index` - The address/account index
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use kobe_eth::{Deriver, DerivationStyle};
    ///
    /// let deriver = Deriver::new(&wallet);
    ///
    /// // Standard (MetaMask/Trezor) path
    /// let addr = deriver.derive_with_style(DerivationStyle::Standard, 0).unwrap();
    ///
    /// // Ledger Live path
    /// let addr = deriver.derive_with_style(DerivationStyle::LedgerLive, 0).unwrap();
    /// ```
    #[inline]
    pub fn derive_with_style(
        &self,
        style: DerivationStyle,
        index: u32,
    ) -> Result<DerivedAddress, Error> {
        self.derive_at_path(&style.path(index))
    }

    /// Derive multiple addresses using a specific wallet derivation style.
    ///
    /// # Arguments
    ///
    /// * `style` - The derivation style to use
    /// * `start_index` - Starting index
    /// * `count` - Number of addresses to derive
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
            .map(|index| self.derive_with_style(style, index))
            .collect()
    }

    /// Derive a private key at the given path using bip32 crate.
    fn derive_key(&self, path: &str) -> Result<SigningKey, Error> {
        // Parse derivation path
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| Error::Derivation(format!("invalid derivation path: {e}")))?;

        // Derive from seed directly using path
        let derived = XPrv::derive_from_path(self.wallet.seed(), &derivation_path)
            .map_err(|e| Error::Derivation(format!("key derivation failed: {e}")))?;

        // Get signing key (XPrv wraps k256::ecdsa::SigningKey)
        Ok(derived.private_key().clone())
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
    fn test_derive_address() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let addr = deriver.derive(0, false, 0).unwrap();

        assert!(addr.address.starts_with("0x"));
        assert_eq!(addr.address.len(), 42);
        assert_eq!(addr.path, "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_derive_multiple() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let addrs = deriver.derive_many(0, false, 0, 5).unwrap();

        assert_eq!(addrs.len(), 5);

        // All addresses should be unique
        let mut seen = alloc::vec::Vec::new();
        for addr in &addrs {
            assert!(!seen.contains(&addr.address));
            seen.push(addr.address.clone());
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn test_deterministic_derivation() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();

        let deriver1 = Deriver::new(&wallet1);
        let deriver2 = Deriver::new(&wallet2);

        let addr1 = deriver1.derive(0, false, 0).unwrap();
        let addr2 = deriver2.derive(0, false, 0).unwrap();

        assert_eq!(addr1.address, addr2.address);
    }

    #[test]
    fn test_passphrase_changes_addresses() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("password")).unwrap();

        let deriver1 = Deriver::new(&wallet1);
        let deriver2 = Deriver::new(&wallet2);

        let addr1 = deriver1.derive(0, false, 0).unwrap();
        let addr2 = deriver2.derive(0, false, 0).unwrap();

        // Same mnemonic with different passphrase should produce different addresses
        assert_ne!(addr1.address, addr2.address);
    }

    #[test]
    fn test_derive_with_style_standard() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);

        let addr = deriver
            .derive_with_style(DerivationStyle::Standard, 0)
            .unwrap();
        assert_eq!(addr.path, "m/44'/60'/0'/0/0");

        let addr = deriver
            .derive_with_style(DerivationStyle::Standard, 5)
            .unwrap();
        assert_eq!(addr.path, "m/44'/60'/0'/0/5");
    }

    #[test]
    fn test_derive_with_style_ledger_live() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);

        let addr = deriver
            .derive_with_style(DerivationStyle::LedgerLive, 0)
            .unwrap();
        assert_eq!(addr.path, "m/44'/60'/0'/0/0");

        let addr = deriver
            .derive_with_style(DerivationStyle::LedgerLive, 1)
            .unwrap();
        assert_eq!(addr.path, "m/44'/60'/1'/0/0");
    }

    #[test]
    fn test_derive_with_style_ledger_legacy() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);

        let addr = deriver
            .derive_with_style(DerivationStyle::LedgerLegacy, 0)
            .unwrap();
        assert_eq!(addr.path, "m/44'/60'/0'/0");

        let addr = deriver
            .derive_with_style(DerivationStyle::LedgerLegacy, 3)
            .unwrap();
        assert_eq!(addr.path, "m/44'/60'/0'/3");
    }

    #[test]
    fn test_different_styles_produce_different_addresses() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);

        let standard = deriver
            .derive_with_style(DerivationStyle::Standard, 1)
            .unwrap();
        let ledger_live = deriver
            .derive_with_style(DerivationStyle::LedgerLive, 1)
            .unwrap();
        let ledger_legacy = deriver
            .derive_with_style(DerivationStyle::LedgerLegacy, 1)
            .unwrap();

        // Different paths should produce different addresses
        assert_ne!(standard.address, ledger_live.address);
        assert_ne!(standard.address, ledger_legacy.address);
        assert_ne!(ledger_live.address, ledger_legacy.address);
    }

    #[test]
    fn test_derive_many_with_style() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);

        let addrs = deriver
            .derive_many_with_style(DerivationStyle::LedgerLive, 0, 3)
            .unwrap();

        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0].path, "m/44'/60'/0'/0/0");
        assert_eq!(addrs[1].path, "m/44'/60'/1'/0/0");
        assert_eq!(addrs[2].path, "m/44'/60'/2'/0/0");
    }
}
