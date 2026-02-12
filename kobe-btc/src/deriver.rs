//! Bitcoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::marker::PhantomData;

use bitcoin::{PrivateKey, bip32::Xpriv, key::CompressedPublicKey};
use kobe::Wallet;
use zeroize::Zeroizing;

use crate::address::create_address;
use crate::{AddressType, DerivationPath, Error, Network};

/// Bitcoin address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe::Wallet`] and derives
/// Bitcoin addresses following BIP32/44/49/84 standards.
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

    /// Derive a Bitcoin address using P2WPKH (Native SegWit) by default.
    ///
    /// Uses path: `m/84'/0'/0'/0/{index}` for mainnet
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
        self.derive_with(AddressType::P2wpkh, index)
    }

    /// Derive a Bitcoin address with a specific address type.
    ///
    /// This method supports different address formats:
    /// - **P2pkh** (Legacy): `m/44'/coin'/0'/0/{index}`
    /// - **P2shP2wpkh** (Nested SegWit): `m/49'/coin'/0'/0/{index}`
    /// - **P2wpkh** (Native SegWit): `m/84'/coin'/0'/0/{index}`
    /// - **P2tr** (Taproot): `m/86'/coin'/0'/0/{index}`
    ///
    /// # Arguments
    ///
    /// * `address_type` - Type of address (determines BIP purpose: 44/49/84/86)
    /// * `index` - The address index
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    #[inline]
    pub fn derive_with(
        &self,
        address_type: AddressType,
        index: u32,
    ) -> Result<DerivedAddress, Error> {
        let path = DerivationPath::bip_standard(address_type, self.network, 0, false, index);
        self.derive_path(&path, address_type)
    }

    /// Derive multiple addresses using P2WPKH (Native SegWit) by default.
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
        self.derive_many_with(AddressType::P2wpkh, start, count)
    }

    /// Derive multiple addresses with a specific address type.
    ///
    /// # Arguments
    ///
    /// * `address_type` - Type of address to derive
    /// * `start` - Starting index
    /// * `count` - Number of addresses to derive
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails.
    pub fn derive_many_with(
        &self,
        address_type: AddressType,
        start: u32,
        count: u32,
    ) -> Result<Vec<DerivedAddress>, Error> {
        (start..start + count)
            .map(|index| self.derive_with(address_type, index))
            .collect()
    }

    /// Derive an address at a custom derivation path.
    ///
    /// This is the lowest-level derivation method, allowing full control
    /// over the derivation path.
    ///
    /// # Arguments
    ///
    /// * `path` - BIP-32 derivation path
    /// * `address_type` - Type of address to generate
    ///
    /// # Errors
    ///
    /// Returns an error if derivation fails.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal circumstances.
    /// The internal `expect` is guaranteed to succeed for valid private keys.
    pub fn derive_path(
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
    fn test_derive_default() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive(0).unwrap();

        // Default is P2WPKH
        assert!(addr.address.starts_with("bc1q"));
        assert_eq!(addr.path.to_string(), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_with_p2wpkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive_with(AddressType::P2wpkh, 0).unwrap();

        assert!(addr.address.starts_with("bc1q"));
        assert_eq!(addr.path.to_string(), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_with_p2pkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive_with(AddressType::P2pkh, 0).unwrap();

        assert!(addr.address.starts_with('1'));
        assert_eq!(addr.path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_with_p2sh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive_with(AddressType::P2shP2wpkh, 0).unwrap();

        assert!(addr.address.starts_with('3'));
        assert_eq!(addr.path.to_string(), "m/49'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_with_p2tr() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive_with(AddressType::P2tr, 0).unwrap();

        assert!(addr.address.starts_with("bc1p"));
        assert_eq!(addr.path.to_string(), "m/86'/0'/0'/0/0");
    }

    #[test]
    fn test_derive_testnet() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Testnet).unwrap();
        let addr = deriver.derive(0).unwrap();

        assert!(addr.address.starts_with("tb1q"));
        assert_eq!(addr.path.to_string(), "m/84'/1'/0'/0/0");
    }

    #[test]
    fn test_derive_many() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addrs = deriver.derive_many(0, 5).unwrap();

        assert_eq!(addrs.len(), 5);

        // All addresses should be unique
        let mut seen = Vec::new();
        for addr in &addrs {
            assert!(!seen.contains(&addr.address));
            seen.push(addr.address.clone());
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn test_derive_many_with() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addrs = deriver.derive_many_with(AddressType::P2pkh, 0, 3).unwrap();

        assert_eq!(addrs.len(), 3);
        for addr in &addrs {
            assert!(addr.address.starts_with('1'));
        }
    }

    #[test]
    fn test_passphrase_changes_addresses() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("password")).unwrap();

        let deriver1 = Deriver::new(&wallet1, Network::Mainnet).unwrap();
        let deriver2 = Deriver::new(&wallet2, Network::Mainnet).unwrap();

        let addr1 = deriver1.derive(0).unwrap();
        let addr2 = deriver2.derive(0).unwrap();

        // Same mnemonic with different passphrase should produce different addresses
        assert_ne!(addr1.address, addr2.address);
    }
}
