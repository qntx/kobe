//! Bitcoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use bitcoin::{Address, PrivateKey, PublicKey, bip32::Xpriv, key::CompressedPublicKey};
use core::marker::PhantomData;
use kobe_core::Wallet;
use zeroize::Zeroizing;

use crate::{AddressType, DerivationPath, Error, Network};

/// Bitcoin address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe_core::Wallet`] and derives
/// Bitcoin addresses following BIP32/44/49/84 standards.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Master extended private key.
    master_key: Xpriv,
    /// Network.
    network: Network,
    /// Reference to the wallet (for lifetime tracking).
    _wallet: PhantomData<&'a Wallet>,
}

/// A derived Bitcoin address with associated keys.
#[derive(Debug)]
pub struct DerivedAddress {
    /// Derivation path used.
    pub path: DerivationPath,
    /// Private key in WIF format.
    pub private_key_wif: Zeroizing<String>,
    /// Public key in hex format.
    pub public_key_hex: String,
    /// Bitcoin address.
    pub address: String,
    /// Address type.
    pub address_type: AddressType,
}

impl<'a> Deriver<'a> {
    /// Create a new Bitcoin deriver from a wallet.
    ///
    /// # Errors
    ///
    /// Returns an error if the master key derivation fails.
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

        let address = Self::create_address(&public_key, self.network, address_type);

        Ok(DerivedAddress {
            path: path.clone(),
            private_key_wif: Zeroizing::new(private_key.to_wif()),
            public_key_hex: public_key.to_string(),
            address: address.to_string(),
            address_type,
        })
    }

    /// Derive multiple addresses in sequence.
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

    /// Create an address from a public key.
    fn create_address(
        public_key: &CompressedPublicKey,
        network: Network,
        address_type: AddressType,
    ) -> Address {
        let btc_network = network.to_bitcoin_network();

        match address_type {
            AddressType::P2pkh => Address::p2pkh(PublicKey::from(*public_key), btc_network),
            AddressType::P2shP2wpkh => Address::p2shwpkh(public_key, btc_network),
            AddressType::P2wpkh => Address::p2wpkh(public_key, btc_network),
        }
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
