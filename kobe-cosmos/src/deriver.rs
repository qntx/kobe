//! Cosmos address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use bip32::{DerivationPath, XPrv};
use k256::ecdsa::SigningKey;
use kobe::Wallet;
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

/// Default bech32 human-readable part for Cosmos Hub.
const DEFAULT_HRP: &str = "cosmos";

/// Cosmos address deriver from a unified wallet seed.
///
/// Derives Cosmos-compatible addresses using BIP-44 path `m/44'/118'/0'/0/{index}`.
/// Supports configurable bech32 prefixes for different Cosmos chains
/// (e.g. "cosmos", "osmo", "atom").
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
    /// Bech32 human-readable part (e.g. "cosmos").
    hrp: String,
}

/// A derived Cosmos address with associated key material.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DerivedAddress {
    /// Derivation path used (e.g. `m/44'/118'/0'/0/0`).
    pub path: String,
    /// Private key in hex format (zeroized on drop).
    pub private_key_hex: Zeroizing<String>,
    /// Compressed public key in hex format.
    pub public_key_hex: String,
    /// Bech32-encoded Cosmos address.
    pub address: String,
}

impl<'a> Deriver<'a> {
    /// Create a new Cosmos deriver with the default "cosmos" prefix.
    #[must_use]
    pub fn new(wallet: &'a Wallet) -> Self {
        Self {
            wallet,
            hrp: DEFAULT_HRP.to_string(),
        }
    }

    /// Create a new Cosmos deriver with a custom bech32 prefix.
    #[must_use]
    pub fn with_hrp(wallet: &'a Wallet, hrp: &str) -> Self {
        Self {
            wallet,
            hrp: hrp.to_string(),
        }
    }

    /// Derive an address at the given account index.
    ///
    /// Uses BIP-44 path: `m/44'/118'/0'/0/{index}`
    pub fn derive(&self, index: u32) -> Result<DerivedAddress, Error> {
        let path = format!("m/44'/118'/0'/0/{index}");
        self.derive_path(&path)
    }

    /// Derive `count` accounts starting at `start`.
    pub fn derive_many(&self, start: u32, count: u32) -> Result<Vec<DerivedAddress>, Error> {
        (start
            ..start
                .checked_add(count)
                .ok_or_else(|| Error::Derivation("index overflow".into()))?)
            .map(|i| self.derive(i))
            .collect()
    }

    /// Derive an address at a custom derivation path.
    pub fn derive_path(&self, path: &str) -> Result<DerivedAddress, Error> {
        let derivation_path: DerivationPath = path
            .parse()
            .map_err(|e| Error::Derivation(format!("invalid derivation path: {e}")))?;

        let derived = XPrv::derive_from_path(self.wallet.seed(), &derivation_path)
            .map_err(|e| Error::Derivation(format!("key derivation failed: {e}")))?;

        let signing_key: &SigningKey = derived.private_key();
        let verifying_key = signing_key.verifying_key();
        let pubkey_compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();

        let address = encode_bech32_address(&self.hrp, pubkey_bytes)?;

        Ok(DerivedAddress {
            path: path.to_string(),
            private_key_hex: Zeroizing::new(hex::encode(signing_key.to_bytes())),
            public_key_hex: hex::encode(pubkey_bytes),
            address,
        })
    }
}

/// Hash160: SHA-256 then RIPEMD-160.
fn hash160(data: &[u8]) -> Vec<u8> {
    Ripemd160::digest(Sha256::digest(data)).to_vec()
}

/// Encode a compressed public key as a bech32 Cosmos address.
fn encode_bech32_address(hrp: &str, compressed_pubkey: &[u8]) -> Result<String, Error> {
    let hash = hash160(compressed_pubkey);
    let hrp_parsed =
        bech32::Hrp::parse(hrp).map_err(|e| Error::AddressEncoding(format!("invalid HRP: {e}")))?;
    bech32::encode::<bech32::Bech32>(hrp_parsed, &hash)
        .map_err(|e| Error::AddressEncoding(format!("bech32 encoding failed: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    #[test]
    fn derive_produces_valid_address() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let derived = deriver.derive(0).unwrap();

        assert!(derived.address.starts_with("cosmos1"));
        assert_eq!(derived.path, "m/44'/118'/0'/0/0");
    }

    #[test]
    fn deterministic_derivation() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();

        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_eq!(a1.address, a2.address);
    }

    #[test]
    fn different_indices_differ() {
        let wallet = test_wallet();
        let deriver = Deriver::new(&wallet);
        let a0 = deriver.derive(0).unwrap();
        let a1 = deriver.derive(1).unwrap();
        assert_ne!(a0.address, a1.address);
    }

    #[test]
    fn custom_hrp() {
        let wallet = test_wallet();
        let deriver = Deriver::with_hrp(&wallet, "osmo");
        let derived = deriver.derive(0).unwrap();
        assert!(derived.address.starts_with("osmo1"));
    }

    #[test]
    fn same_hash_different_prefix() {
        let wallet = test_wallet();
        let cosmos = Deriver::new(&wallet).derive(0).unwrap();
        let osmo = Deriver::with_hrp(&wallet, "osmo").derive(0).unwrap();

        let (_, cosmos_data) = bech32::decode(&cosmos.address).unwrap();
        let (_, osmo_data) = bech32::decode(&osmo.address).unwrap();
        assert_eq!(cosmos_data, osmo_data);
    }

    #[test]
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("pass")).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_ne!(a1.address, a2.address);
    }
}
