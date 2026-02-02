//! Standard (non-HD) Bitcoin wallet implementation.
//!
//! A standard wallet uses a single randomly generated private key,
//! without mnemonic or HD derivation.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

use bitcoin::{Address, NetworkKind, PrivateKey, key::CompressedPublicKey};
use zeroize::Zeroizing;

use crate::address::create_address;
use crate::{AddressType, Error, Network};

/// A standard Bitcoin wallet with a single private key.
///
/// This wallet type generates a random private key directly,
/// without using a mnemonic or HD derivation.
///
/// # Example
///
/// ```ignore
/// use kobe_btc::{StandardWallet, Network, AddressType};
///
/// let wallet = StandardWallet::generate(Network::Mainnet, AddressType::P2wpkh).unwrap();
/// println!("Address: {}", wallet.address_string());
/// println!("Private Key (WIF): {}", wallet.private_key_wif().as_str());
/// ```
#[derive(Debug)]
pub struct StandardWallet {
    /// Bitcoin private key.
    private_key: PrivateKey,
    /// Compressed public key derived from private key.
    public_key: CompressedPublicKey,
    /// Bitcoin address.
    address: Address,
    /// Bitcoin network (mainnet or testnet).
    network: Network,
    /// Address type used for this wallet.
    address_type: AddressType,
}

impl StandardWallet {
    /// Generate a new standard wallet with a random private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal circumstances.
    /// The internal `expect` is guaranteed to succeed for valid private keys.
    ///
    /// # Note
    ///
    /// This function requires the `rand` feature to be enabled.
    #[cfg(feature = "rand")]
    pub fn generate(network: Network, address_type: AddressType) -> Result<Self, Error> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());

        let private_key = PrivateKey::new(secret_key, network.to_bitcoin_network());
        let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
            .expect("valid private key always produces valid public key");

        let address = create_address(&public_key, network, address_type);

        Ok(Self {
            private_key,
            public_key,
            address,
            network,
            address_type,
        })
    }

    /// Import a wallet from a WIF (Wallet Import Format) private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the WIF is invalid.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal circumstances.
    /// The internal `expect` is guaranteed to succeed for valid private keys.
    pub fn from_wif(wif: &str, address_type: AddressType) -> Result<Self, Error> {
        let private_key: PrivateKey = wif.parse().map_err(|_| Error::InvalidWif)?;

        let network = if private_key.network == NetworkKind::Main {
            Network::Mainnet
        } else {
            Network::Testnet
        };

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
            .expect("valid private key always produces valid public key");

        let address = create_address(&public_key, network, address_type);

        Ok(Self {
            private_key,
            public_key,
            address,
            network,
            address_type,
        })
    }

    /// Import a wallet from a hex-encoded private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid.
    ///
    /// # Panics
    ///
    /// This function will not panic under normal circumstances.
    /// The internal `expect` is guaranteed to succeed for valid private keys.
    pub fn from_private_key_hex(
        hex_str: &str,
        network: Network,
        address_type: AddressType,
    ) -> Result<Self, Error> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|_| Error::InvalidHex)?;

        if bytes.len() != 32 {
            return Err(Error::InvalidPrivateKey);
        }

        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&bytes)
            .map_err(|_| Error::InvalidPrivateKey)?;

        let private_key = PrivateKey::new(secret_key, network.to_bitcoin_network());

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
            .expect("valid private key always produces valid public key");

        let address = create_address(&public_key, network, address_type);

        Ok(Self {
            private_key,
            public_key,
            address,
            network,
            address_type,
        })
    }

    /// Get the private key in hex format (zeroized on drop).
    #[inline]
    #[must_use]
    pub fn private_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.private_key.inner.secret_bytes()))
    }

    /// Get the private key in WIF format (zeroized on drop).
    #[inline]
    #[must_use]
    pub fn private_key_wif(&self) -> Zeroizing<String> {
        Zeroizing::new(self.private_key.to_wif())
    }

    /// Get the public key in compressed hex format.
    #[inline]
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.public_key.to_string()
    }

    /// Get the Bitcoin address.
    #[must_use]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Get the address as a string.
    #[inline]
    #[must_use]
    pub fn address_string(&self) -> String {
        self.address.to_string()
    }

    /// Get the network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Get the address type.
    #[must_use]
    pub const fn address_type(&self) -> AddressType {
        self.address_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_mainnet_p2wpkh() {
        let wallet = StandardWallet::generate(Network::Mainnet, AddressType::P2wpkh).unwrap();
        assert!(wallet.address_string().starts_with("bc1q"));
        assert_eq!(wallet.network(), Network::Mainnet);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_mainnet_p2pkh() {
        let wallet = StandardWallet::generate(Network::Mainnet, AddressType::P2pkh).unwrap();
        assert!(wallet.address_string().starts_with('1'));
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_mainnet_p2sh() {
        let wallet = StandardWallet::generate(Network::Mainnet, AddressType::P2shP2wpkh).unwrap();
        assert!(wallet.address_string().starts_with('3'));
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_mainnet_p2tr() {
        let wallet = StandardWallet::generate(Network::Mainnet, AddressType::P2tr).unwrap();
        assert!(wallet.address_string().starts_with("bc1p"));
    }

    #[cfg(feature = "rand")]
    #[test]
    fn test_generate_testnet() {
        let wallet = StandardWallet::generate(Network::Testnet, AddressType::P2wpkh).unwrap();
        assert!(wallet.address_string().starts_with("tb1q"));
    }
}
