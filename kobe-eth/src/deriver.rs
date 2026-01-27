//! Ethereum address derivation from a unified wallet.

use hmac::{Hmac, Mac};
use k256::{Scalar, ecdsa::SigningKey, elliptic_curve::PrimeField};
use kobe_core::Wallet;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::Error;
use crate::utils::{public_key_to_address, to_checksum_address};

type HmacSha512 = Hmac<Sha512>;

/// Ethereum address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe_core::Wallet`] and derives
/// Ethereum addresses following BIP32/44 standards.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet.
    wallet: &'a Wallet,
}

/// A derived Ethereum address with associated keys.
#[derive(Debug)]
pub struct DerivedAddress {
    /// Derivation path used.
    pub path: String,
    /// Private key in hex format (without 0x prefix).
    pub private_key_hex: Zeroizing<String>,
    /// Public key in hex format (uncompressed).
    pub public_key_hex: String,
    /// Checksummed Ethereum address.
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
    pub fn derive(
        &self,
        account: u32,
        change: bool,
        address_index: u32,
    ) -> Result<DerivedAddress, Error> {
        let change_val = if change { 1 } else { 0 };
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

    /// Derive a private key at the given path.
    fn derive_key(&self, path: &str) -> Result<SigningKey, Error> {
        // Parse path
        let path_str = path.strip_prefix("m/").unwrap_or(path);
        let indices: Result<Vec<u32>, _> = path_str
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|component| {
                let (num_str, hardened) = if let Some(s) = component.strip_suffix('\'') {
                    (s, true)
                } else if let Some(s) = component.strip_suffix('h') {
                    (s, true)
                } else {
                    (component, false)
                };

                num_str
                    .parse::<u32>()
                    .map(|n| if hardened { n | 0x8000_0000 } else { n })
                    .map_err(|_| Error::Derivation(format!("invalid path component: {component}")))
            })
            .collect();

        let indices = indices?;

        // Master key derivation
        let mut mac =
            HmacSha512::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");
        mac.update(self.wallet.seed());
        let result = mac.finalize().into_bytes();

        let mut key = result[..32].to_vec();
        let mut chain_code = result[32..].to_vec();

        // Derive child keys
        for index in indices {
            let mut mac =
                HmacSha512::new_from_slice(&chain_code).expect("HMAC can take key of any size");

            if index & 0x8000_0000 != 0 {
                // Hardened derivation
                mac.update(&[0u8]);
                mac.update(&key);
            } else {
                // Normal derivation
                let signing_key =
                    SigningKey::from_slice(&key).map_err(|_| Error::InvalidPrivateKey)?;
                let public_key = signing_key.verifying_key().to_encoded_point(true);
                mac.update(public_key.as_bytes());
            }
            mac.update(&index.to_be_bytes());

            let result = mac.finalize().into_bytes();
            let il = &result[..32];

            // Add il to key mod n
            let il_arr: [u8; 32] = (*il)
                .try_into()
                .map_err(|_| Error::Derivation("invalid IL length".to_string()))?;
            let key_arr: [u8; 32] = key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Derivation("invalid key length".to_string()))?;

            let il_scalar = Scalar::from_repr(il_arr.into());
            let key_scalar = Scalar::from_repr(key_arr.into());

            if il_scalar.is_none().into() || key_scalar.is_none().into() {
                return Err(Error::Derivation("invalid scalar".to_string()));
            }

            let new_key = il_scalar.unwrap() + key_scalar.unwrap();
            key = new_key.to_bytes().to_vec();
            chain_code = result[32..].to_vec();
        }

        SigningKey::from_slice(&key).map_err(|_| Error::InvalidPrivateKey)
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
        let unique: std::collections::HashSet<_> = addrs.iter().map(|a| &a.address).collect();
        assert_eq!(unique.len(), 5);
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
}
