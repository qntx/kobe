//! Bitcoin address creation utilities.
//!
//! This module provides shared address creation functionality used by both
//! HD derivation and standard wallet implementations.

use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, PublicKey};

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
pub(crate) fn create_address(
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
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    use super::*;

    fn test_pubkey() -> CompressedPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(
            &hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap(),
        )
        .unwrap();
        let pk = bitcoin::PrivateKey::new(sk, bitcoin::Network::Bitcoin);
        CompressedPublicKey::from_private_key(&secp, &pk).expect("valid key")
    }

    #[test]
    fn p2wpkh_starts_with_bc1q() {
        let addr = create_address(&test_pubkey(), Network::Mainnet, AddressType::P2wpkh);
        assert!(addr.to_string().starts_with("bc1q"));
    }

    #[test]
    fn p2pkh_starts_with_1() {
        let addr = create_address(&test_pubkey(), Network::Mainnet, AddressType::P2pkh);
        assert!(addr.to_string().starts_with('1'));
    }

    #[test]
    fn p2sh_starts_with_3() {
        let addr = create_address(&test_pubkey(), Network::Mainnet, AddressType::P2shP2wpkh);
        assert!(addr.to_string().starts_with('3'));
    }

    #[test]
    fn p2tr_starts_with_bc1p() {
        let addr = create_address(&test_pubkey(), Network::Mainnet, AddressType::P2tr);
        assert!(addr.to_string().starts_with("bc1p"));
    }

    #[test]
    fn testnet_p2wpkh_starts_with_tb1q() {
        let addr = create_address(&test_pubkey(), Network::Testnet, AddressType::P2wpkh);
        assert!(addr.to_string().starts_with("tb1q"));
    }
}
