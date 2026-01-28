//! Bitcoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bitcoin::{PrivateKey, bip32::Xpriv, key::CompressedPublicKey};
use core::marker::PhantomData;
use kobe_core::Wallet;
use zeroize::Zeroizing;

use crate::address::create_address;
use crate::{AddressType, DerivationPath, Error, Network};

/// Bitcoin address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe_core::Wallet`] and derives
/// Bitcoin addresses following BIP32/44/49/84 standards.
///
/// # Example
///
/// ```
/// use kobe_core::Wallet;
/// use kobe_btc::{Deriver, Network, AddressType};
///
/// let wallet = Wallet::generate(12, None).unwrap();
/// let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
/// let addr = deriver.derive(AddressType::P2wpkh, 0, false, 0).unwrap();
/// println!("Address: {}", addr.address);
/// ```
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Master extended private key.
    master_key: Xpriv,
    /// Bitcoin network (mainnet or testnet).
    network: Network,
    /// Phantom data to track wallet lifetime.
    _wallet: PhantomData<&'a Wallet>,
}

/// A derived Bitcoin address with associated keys.
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// Derivation path used (e.g., `m/84'/0'/0'/0/0`).
    pub path: DerivationPath,
    /// Private key in hex format (zeroized on drop).
    pub private_key_hex: Zeroizing<String>,
    /// Private key in WIF format (zeroized on drop).
    pub private_key_wif: Zeroizing<String>,
    /// Public key in compressed hex format.
    pub public_key_hex: String,
    /// Bitcoin address string.
    pub address: String,
    /// Address type used for derivation.
    pub address_type: AddressType,
}

impl<'a> Deriver<'a> {
    /// Create a new Bitcoin deriver from a wallet.
    ///
    /// # Errors
    ///
    /// Returns an error if the master key derivation fails.
    #[inline]
    pub fn new(wallet: &'a Wallet, network: Network) -> Result<Self, Error> {
        let master_key = Xpriv::new_master(network.to_bitcoin_network(), wallet.seed())?;

        Ok(Self {
            master_key,
            network,
            _wallet: PhantomData,
        })
    }

    /// Derive an address using BIP44/49/84 standard path.
    ///
    /// # Arguments
    ///
    /// * `address_type` - Type of address (determines BIP purpose: 44/49/84)
    /// * `account` - Account index (usually 0)
    /// * `change` - Whether this is a change address
    /// * `address_index` - Address index within the account
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    pub fn derive(
        &self,
        address_type: AddressType,
        account: u32,
        change: bool,
        address_index: u32,
    ) -> Result<DerivedAddress, Error> {
        let path = DerivationPath::bip_standard(
            address_type,
            self.network,
            account,
            change,
            address_index,
        );
        self.derive_at_path(&path, address_type)
    }

    /// Derive an address at a custom derivation path.
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal circumstances.
    /// The internal `expect` is guaranteed to succeed for valid private keys.
    pub fn derive_at_path(
        &self,
        path: &DerivationPath,
        address_type: AddressType,
    ) -> Result<DerivedAddress, Error> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let derived = self.master_key.derive_priv(&secp, path.inner())?;

        let private_key = PrivateKey::new(derived.private_key, self.network.to_bitcoin_network());
        let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
            .expect("valid private key always produces valid public key");

        let address = create_address(&public_key, self.network, address_type);

        // Get raw private key bytes in hex format
        let private_key_bytes = derived.private_key.secret_bytes();

        Ok(DerivedAddress {
            path: path.clone(),
            private_key_hex: Zeroizing::new(hex::encode(private_key_bytes)),
            private_key_wif: Zeroizing::new(private_key.to_wif()),
            public_key_hex: public_key.to_string(),
            address: address.to_string(),
            address_type,
        })
    }

    /// Derive multiple addresses in sequence.
    ///
    /// # Arguments
    ///
    /// * `address_type` - Type of address to derive
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
        address_type: AddressType,
        account: u32,
        change: bool,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<DerivedAddress>, Error> {
        (start_index..start_index + count)
            .map(|index| self.derive(address_type, account, change, index))
            .collect()
    }

    /// Get the network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
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
    fn test_derive_p2wpkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive(AddressType::P2wpkh, 0, false, 0).unwrap();

        assert!(addr.address.starts_with("bc1q"));
        assert_eq!(addr.path.to_string(), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_p2pkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive(AddressType::P2pkh, 0, false, 0).unwrap();

        assert!(addr.address.starts_with('1'));
        assert_eq!(addr.path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_p2sh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver
            .derive(AddressType::P2shP2wpkh, 0, false, 0)
            .unwrap();

        assert!(addr.address.starts_with('3'));
        assert_eq!(addr.path.to_string(), "m/49'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_p2tr() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive(AddressType::P2tr, 0, false, 0).unwrap();

        assert!(addr.address.starts_with("bc1p"));
        assert_eq!(addr.path.to_string(), "m/86'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_testnet() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Testnet).unwrap();
        let addr = deriver.derive(AddressType::P2wpkh, 0, false, 0).unwrap();

        assert!(addr.address.starts_with("tb1q"));
        assert_eq!(addr.path.to_string(), "m/84'/1'/0'/0/0");
    }

    #[test]
    fn test_derive_multiple() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addrs = deriver
            .derive_many(AddressType::P2wpkh, 0, false, 0, 5)
            .unwrap();

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
    fn test_passphrase_changes_addresses() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("password")).unwrap();

        let deriver1 = Deriver::new(&wallet1, Network::Mainnet).unwrap();
        let deriver2 = Deriver::new(&wallet2, Network::Mainnet).unwrap();

        let addr1 = deriver1.derive(AddressType::P2wpkh, 0, false, 0).unwrap();
        let addr2 = deriver2.derive(AddressType::P2wpkh, 0, false, 0).unwrap();

        // Same mnemonic with different passphrase should produce different addresses
        assert_ne!(addr1.address, addr2.address);
    }
}
