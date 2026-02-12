//! Bitcoin address creation utilities.
//!
//! This module provides shared address creation functionality used by both
//! HD derivation and standard wallet implementations.

use bitcoin::{Address, PublicKey, key::CompressedPublicKey, secp256k1::Secp256k1};

use crate::{AddressType, Network};

/// Create a Bitcoin address from a compressed public key.
///
/// This function handles all supported address types (P2PKH, P2SH-P2WPKH,
/// P2WPKH, and P2TR) and is used by both the HD deriver and standard wallet.
///
/// # Arguments
///
/// * `public_key` - The compressed public key to create an address from
/// * `network` - The Bitcoin network (mainnet or testnet)
/// * `address_type` - The type of address to create
///
/// # Returns
///
/// A Bitcoin address of the specified type.
#[must_use]
pub fn create_address(
    public_key: &CompressedPublicKey,
    network: Network,
    address_type: AddressType,
) -> Address {
    let btc_network = network.to_bitcoin_network();

    match address_type {
        AddressType::P2pkh => Address::p2pkh(PublicKey::from(*public_key), btc_network),
        AddressType::P2shP2wpkh => Address::p2shwpkh(public_key, btc_network),
        AddressType::P2wpkh => Address::p2wpkh(public_key, btc_network),
        AddressType::P2tr => {
            let secp = Secp256k1::verification_only();
            let internal_key = public_key.0.x_only_public_key().0;
            Address::p2tr(&secp, internal_key, None, btc_network)
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::Secp256k1;

    use super::*;

    #[test]
    fn test_create_address_p2wpkh() {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());
        let private_key = bitcoin::PrivateKey::new(secret_key, bitcoin::Network::Bitcoin);
        let public_key =
            CompressedPublicKey::from_private_key(&secp, &private_key).expect("valid key");

        let address = create_address(&public_key, Network::Mainnet, AddressType::P2wpkh);
        assert!(address.to_string().starts_with("bc1q"));
    }

    #[test]
    fn test_create_address_p2pkh() {
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());
        let private_key = bitcoin::PrivateKey::new(secret_key, bitcoin::Network::Bitcoin);
        let public_key =
            CompressedPublicKey::from_private_key(&secp, &private_key).expect("valid key");

        let address = create_address(&public_key, Network::Mainnet, AddressType::P2pkh);
        assert!(address.to_string().starts_with('1'));
    }
}
