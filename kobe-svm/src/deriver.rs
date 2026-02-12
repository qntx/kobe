//! Solana address derivation from HD wallet.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ed25519_dalek::VerifyingKey;
use kobe::Wallet;
use zeroize::Zeroizing;

use crate::Error;
use crate::derivation_style::DerivationStyle;
use crate::slip10::DerivedKey;

/// A derived Solana address with associated keys.
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// Derivation path used (e.g., `m/44'/501'/0'/0'`).
    pub path: String,
    /// Private key in hex format (zeroized on drop).
    pub private_key_hex: Zeroizing<String>,
    /// Full keypair in base58 format (64 bytes: secret 32B + public 32B, zeroized on drop).
    ///
    /// This is the standard format used by Phantom, Backpack, Solflare wallets.
    pub keypair_base58: Zeroizing<String>,
    /// Public key in hex format.
    pub public_key_hex: String,
    /// Solana address (Base58 encoded public key).
    pub address: String,
}

/// Solana address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe::Wallet`] and derives
/// Solana addresses following BIP44/SLIP-0010 standards.
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

    /// Derive a Solana address using the Standard derivation style.
    ///
    /// Uses path: `m/44'/501'/index'/0'` (Phantom, Backpack, etc.)
    ///
    /// # Arguments
    ///
    /// * `index` - The address index
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[inline]
    pub fn derive(&self, index: u32) -> Result<DerivedAddress, Error> {
        self.derive_with(DerivationStyle::Standard, index)
    }

    /// Derive a Solana address with a specific derivation style.
    ///
    /// This method supports different wallet path formats:
    /// - **Standard** (Phantom/Backpack): `m/44'/501'/index'/0'`
    /// - **Trust**: `m/44'/501'/index'`
    /// - **Ledger Live**: `m/44'/501'/index'/0'/0'`
    /// - **Legacy**: `m/44'/501'/0'/index'`
    ///
    /// # Arguments
    ///
    /// * `style` - The derivation style to use
    /// * `index` - The address/account index
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[allow(deprecated)]
    pub fn derive_with(&self, style: DerivationStyle, index: u32) -> Result<DerivedAddress, Error> {
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

        // Build base58-encoded 64-byte keypair (secret 32B + public 32B)
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[..32].copy_from_slice(derived.private_key.as_slice());
        keypair_bytes[32..].copy_from_slice(public_key_bytes);
        let keypair_b58 = bs58::encode(&keypair_bytes).into_string();
        keypair_bytes.fill(0);

        Ok(DerivedAddress {
            path: style.path(index),
            private_key_hex: Zeroizing::new(hex::encode(derived.private_key.as_slice())),
            keypair_base58: Zeroizing::new(keypair_b58),
            public_key_hex: hex::encode(public_key_bytes),
            address: bs58::encode(public_key_bytes).into_string(),
        })
    }

    /// Derive multiple addresses using the Standard derivation style.
    ///
    /// # Arguments
    ///
    /// * `start` - Starting address index
    /// * `count` - Number of addresses to derive
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    #[inline]
    pub fn derive_many(&self, start: u32, count: u32) -> Result<Vec<DerivedAddress>, Error> {
        self.derive_many_with(DerivationStyle::Standard, start, count)
    }

    /// Derive multiple addresses with a specific derivation style.
    ///
    /// # Arguments
    ///
    /// * `style` - The derivation style to use
    /// * `start` - Starting index
    /// * `count` - Number of addresses to derive
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    pub fn derive_many_with(
        &self,
        style: DerivationStyle,
        start: u32,
        count: u32,
    ) -> Result<Vec<DerivedAddress>, Error> {
        (start..start + count)
            .map(|index| self.derive_with(style, index))
            .collect()
    }

    /// Derive an address at a custom derivation path.
    ///
    /// This is the lowest-level derivation method, allowing full control
    /// over the derivation path.
    ///
    /// **Note**: Ed25519 (Solana) only supports hardened derivation.
    /// All path components will be treated as hardened.
    ///
    /// # Arguments
    ///
    /// * `path` - SLIP-0010 derivation path (e.g., `m/44'/501'/0'/0'`)
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    pub fn derive_path(&self, path: &str) -> Result<DerivedAddress, Error> {
        let derived = DerivedKey::derive_path(self.wallet.seed(), path)?;

        let signing_key = derived.to_signing_key();
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let public_key_bytes = verifying_key.as_bytes();

        // Build base58-encoded 64-byte keypair (secret 32B + public 32B)
        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[..32].copy_from_slice(derived.private_key.as_slice());
        keypair_bytes[32..].copy_from_slice(public_key_bytes);
        let keypair_b58 = bs58::encode(&keypair_bytes).into_string();
        keypair_bytes.fill(0);

        Ok(DerivedAddress {
            path: path.to_string(),
            private_key_hex: Zeroizing::new(hex::encode(derived.private_key.as_slice())),
            keypair_base58: Zeroizing::new(keypair_b58),
            public_key_hex: hex::encode(public_key_bytes),
            address: bs58::encode(public_key_bytes).into_string(),
        })
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
    fn test_derive_with_trust() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let addr = deriver.derive_with(DerivationStyle::Trust, 0).unwrap();

        assert_eq!(addr.path, "m/44'/501'/0'");
        assert!(addr.address.len() >= 32 && addr.address.len() <= 44);
    }

    #[test]
    fn test_derive_with_ledger_live() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let addr = deriver.derive_with(DerivationStyle::LedgerLive, 0).unwrap();

        assert_eq!(addr.path, "m/44'/501'/0'/0'/0'");
        assert!(addr.address.len() >= 32 && addr.address.len() <= 44);
    }

    #[test]
    fn test_different_styles_produce_different_addresses() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);

        let standard = deriver.derive_with(DerivationStyle::Standard, 0).unwrap();
        let trust = deriver.derive_with(DerivationStyle::Trust, 0).unwrap();
        let ledger_live = deriver.derive_with(DerivationStyle::LedgerLive, 0).unwrap();
        let legacy = deriver.derive_with(DerivationStyle::Legacy, 0).unwrap();

        // All styles should produce different addresses
        assert_ne!(standard.address, trust.address);
        assert_ne!(standard.address, ledger_live.address);
        assert_ne!(standard.address, legacy.address);
        assert_ne!(trust.address, ledger_live.address);
    }
}
