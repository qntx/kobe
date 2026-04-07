//! Bitcoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::marker::PhantomData;

use bitcoin::{PrivateKey, bip32::Xpriv, key::CompressedPublicKey, secp256k1::Secp256k1};
use kobe_primitives::{Derive, DerivedAccount, Wallet};
use zeroize::Zeroizing;

use crate::address::create_address;
use crate::{AddressType, DerivationPath, DeriveError, Network};

/// Bitcoin address deriver from a unified wallet seed.
///
/// This deriver takes a seed from [`kobe::Wallet`] and derives
/// Bitcoin addresses following BIP32/44/49/84 standards.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Master extended private key.
    master_key: Xpriv,
    /// Cached secp256k1 context (~768KB, reused across derivations).
    secp: Secp256k1<bitcoin::secp256k1::All>,
    /// Bitcoin network (mainnet or testnet).
    network: Network,
    /// Phantom data to track wallet lifetime.
    _wallet: PhantomData<&'a Wallet>,
}

/// A derived Bitcoin address with associated keys and metadata.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    pub fn new(wallet: &'a Wallet, network: Network) -> Result<Self, DeriveError> {
        let master_key = Xpriv::new_master(network.to_bitcoin_network(), wallet.seed())?;

        Ok(Self {
            master_key,
            secp: Secp256k1::new(),
            network,
            _wallet: PhantomData,
        })
    }

    /// Derive a Bitcoin address using P2WPKH (Native `SegWit`) by default.
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
    pub fn derive(&self, index: u32) -> Result<DerivedAddress, DeriveError> {
        self.derive_with(AddressType::P2wpkh, index)
    }

    /// Derive a Bitcoin address with a specific address type.
    ///
    /// This method supports different address formats:
    /// - **P2pkh** (Legacy): `m/44'/coin'/0'/0/{index}`
    /// - **`P2shP2wpkh`** (Nested SegWit): `m/49'/coin'/0'/0/{index}`
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
    ) -> Result<DerivedAddress, DeriveError> {
        let path = DerivationPath::bip_standard(address_type, self.network, 0, false, index)?;
        self.derive_path(&path, address_type)
    }

    /// Derive multiple addresses using P2WPKH (Native `SegWit`) by default.
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
    pub fn derive_many(&self, start: u32, count: u32) -> Result<Vec<DerivedAddress>, DeriveError> {
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
    ) -> Result<Vec<DerivedAddress>, DeriveError> {
        let end = start.checked_add(count).ok_or_else(|| {
            DeriveError::InvalidDerivationPath(
                "index overflow: start + count exceeds u32::MAX".into(),
            )
        })?;
        (start..end)
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
    ) -> Result<DerivedAddress, DeriveError> {
        let derived = self.master_key.derive_priv(&self.secp, path.inner())?;

        let private_key = PrivateKey::new(derived.private_key, self.network.to_bitcoin_network());
        let public_key = CompressedPublicKey::from_private_key(&self.secp, &private_key)
            .map_err(|_| DeriveError::InvalidPrivateKey)?;

        let address = create_address(&public_key, self.network, address_type);

        let private_key_bytes = Zeroizing::new(derived.private_key.secret_bytes());

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

    /// Internal: derive a [`DerivedAccount`] at a string path with default P2WPKH.
    fn derive_account_at_path(&self, path_str: &str) -> Result<DerivedAccount, DeriveError> {
        let path = DerivationPath::from_path_str(path_str)?;
        let da = self.derive_path(&path, AddressType::P2wpkh)?;
        Ok(DerivedAccount::new(
            da.path.to_string(),
            da.private_key_hex,
            da.public_key_hex,
            da.address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        let da = self.derive_with(AddressType::P2wpkh, index)?;
        Ok(DerivedAccount::new(
            da.path.to_string(),
            da.private_key_hex,
            da.public_key_hex,
            da.address,
        ))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_account_at_path(path)
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
    fn kat_p2wpkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive_with(AddressType::P2wpkh, 0).unwrap();
        assert_eq!(addr.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(addr.path.to_string(), "m/84'/0'/0'/0/0");
    }

    #[test]
    fn kat_p2pkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive_with(AddressType::P2pkh, 0).unwrap();
        assert_eq!(addr.address, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
        assert_eq!(addr.path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn kat_p2sh_p2wpkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive_with(AddressType::P2shP2wpkh, 0).unwrap();
        assert_eq!(addr.address, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
        assert_eq!(addr.path.to_string(), "m/49'/0'/0'/0/0");
    }

    #[test]
    fn p2tr_prefix() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addr = deriver.derive_with(AddressType::P2tr, 0).unwrap();
        assert!(addr.address.starts_with("bc1p"));
        assert_eq!(addr.path.to_string(), "m/86'/0'/0'/0/0");
    }

    #[test]
    fn derive_default_is_p2wpkh() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let def = deriver.derive(0).unwrap();
        let explicit = deriver.derive_with(AddressType::P2wpkh, 0).unwrap();
        assert_eq!(def.address, explicit.address);
    }

    #[test]
    fn testnet_prefix() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Testnet).unwrap();
        let addr = deriver.derive(0).unwrap();
        assert!(addr.address.starts_with("tb1q"));
        assert_eq!(addr.path.to_string(), "m/84'/1'/0'/0/0");
    }

    #[test]
    fn derive_many_unique() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
        let addrs = deriver.derive_many(0, 5).unwrap();
        assert_eq!(addrs.len(), 5);
        let mut unique: Vec<_> = addrs.iter().map(|a| &a.address).collect();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 5);
    }

    #[test]
    fn passphrase_changes_addresses() {
        let wallet1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let wallet2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("password")).unwrap();
        let d1 = Deriver::new(&wallet1, Network::Mainnet).unwrap();
        let d2 = Deriver::new(&wallet2, Network::Mainnet).unwrap();
        assert_ne!(d1.derive(0).unwrap().address, d2.derive(0).unwrap().address);
    }
}
