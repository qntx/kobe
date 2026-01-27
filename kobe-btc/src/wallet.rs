//! Standard (non-HD) Bitcoin wallet implementation.
//!
//! A standard wallet uses a single randomly generated private key.

use bitcoin::{Address, NetworkKind, PrivateKey, PublicKey, key::CompressedPublicKey};
use zeroize::Zeroizing;

use crate::{AddressType, Error, Network};

/// A standard Bitcoin wallet with a single private key.
///
/// This wallet type generates a random private key directly,
/// without using a mnemonic or HD derivation.
#[derive(Debug)]
pub struct StandardWallet {
    /// Private key.
    private_key: PrivateKey,
    /// Compressed public key.
    public_key: CompressedPublicKey,
    /// Bitcoin address.
    address: Address,
    /// Network.
    network: Network,
    /// Address type.
    address_type: AddressType,
}

impl StandardWallet {
    /// Generate a new standard wallet with a random private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate(network: Network, address_type: AddressType) -> Result<Self, Error> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());

        let private_key = PrivateKey::new(secret_key, network.to_bitcoin_network());
        let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
            .expect("valid private key always produces valid public key");

        let address = Self::create_address(&public_key, network, address_type);

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
    pub fn from_wif(wif: &str, address_type: AddressType) -> Result<Self, Error> {
        let private_key: PrivateKey = wif
            .parse()
            .map_err(|_| Error::InvalidDerivationPath("invalid WIF format".to_string()))?;

        let network = if private_key.network == NetworkKind::Main {
            Network::Mainnet
        } else {
            Network::Testnet
        };

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
            .expect("valid private key always produces valid public key");

        let address = Self::create_address(&public_key, network, address_type);

        Ok(Self {
            private_key,
            public_key,
            address,
            network,
            address_type,
        })
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

    /// Get the private key in WIF format.
    #[must_use]
    pub fn private_key_wif(&self) -> Zeroizing<String> {
        Zeroizing::new(self.private_key.to_wif())
    }

    /// Get the public key in hex format.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.public_key.to_string()
    }

    /// Get the Bitcoin address.
    #[must_use]
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the address as a string.
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

    #[test]
    fn test_generate_mainnet_p2wpkh() {
        let wallet = StandardWallet::generate(Network::Mainnet, AddressType::P2wpkh).unwrap();
        assert!(wallet.address_string().starts_with("bc1q"));
        assert_eq!(wallet.network(), Network::Mainnet);
    }

    #[test]
    fn test_generate_mainnet_p2pkh() {
        let wallet = StandardWallet::generate(Network::Mainnet, AddressType::P2pkh).unwrap();
        assert!(wallet.address_string().starts_with('1'));
    }

    #[test]
    fn test_generate_mainnet_p2sh() {
        let wallet = StandardWallet::generate(Network::Mainnet, AddressType::P2shP2wpkh).unwrap();
        assert!(wallet.address_string().starts_with('3'));
    }

    #[test]
    fn test_generate_testnet() {
        let wallet = StandardWallet::generate(Network::Testnet, AddressType::P2wpkh).unwrap();
        assert!(wallet.address_string().starts_with("tb1q"));
    }
}
