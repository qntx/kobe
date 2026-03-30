//! Cosmos address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use bip32::{DerivationPath, XPrv};
use k256::ecdsa::SigningKey;
pub use kobe::DerivedAccount;
use kobe::{Derive, Wallet};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

/// Cosmos address deriver.
///
/// Configurable bech32 prefix (`hrp`) and BIP-44 coin type for different
/// Cosmos SDK chains (ATOM=118, Osmosis=118, Terra=330, etc.).
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Wallet seed reference.
    wallet: &'a Wallet,
    /// Bech32 human-readable part.
    hrp: String,
    /// BIP-44 coin type (default 118 for Cosmos Hub).
    coin_type: u32,
}

impl<'a> Deriver<'a> {
    /// Create a Cosmos Hub deriver (`cosmos1...`, coin_type 118).
    #[must_use]
    pub fn new(wallet: &'a Wallet) -> Self {
        Self {
            wallet,
            hrp: "cosmos".to_string(),
            coin_type: 118,
        }
    }

    /// Create a deriver with custom bech32 prefix and coin type.
    ///
    /// # Examples
    /// - Osmosis: `Deriver::with_config(&w, "osmo", 118)`
    /// - Terra: `Deriver::with_config(&w, "terra", 330)`
    #[must_use]
    pub fn with_config(wallet: &'a Wallet, hrp: &str, coin_type: u32) -> Self {
        Self {
            wallet,
            hrp: hrp.to_string(),
            coin_type,
        }
    }

    /// Derive at an arbitrary path (internal).
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        let dp: DerivationPath = path
            .parse()
            .map_err(|e| Error::Derivation(format!("invalid path: {e}")))?;
        let xprv = XPrv::derive_from_path(self.wallet.seed(), &dp)
            .map_err(|e| Error::Derivation(format!("derivation failed: {e}")))?;

        let signing_key: &SigningKey = xprv.private_key();
        let verifying_key = signing_key.verifying_key();
        let pubkey_compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();
        let address = encode_bech32_address(&self.hrp, pubkey_bytes)?;

        Ok(DerivedAccount::new(
            path.to_string(),
            Zeroizing::new(hex::encode(signing_key.to_bytes())),
            hex::encode(pubkey_bytes),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = Error;

    fn derive(&self, index: u32) -> Result<DerivedAccount, Error> {
        let path = format!("m/44'/{}'/{index}'/0/0", self.coin_type);
        self.derive_at_path(&path)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        self.derive_at_path(path)
    }

    fn overflow_error(&self) -> Error {
        Error::Derivation("index overflow".into())
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

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> Wallet {
        Wallet::from_mnemonic(MNEMONIC, None).unwrap()
    }

    #[test]
    fn cosmos_hub_address() {
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        assert!(a.address.starts_with("cosmos1"));
    }

    #[test]
    fn deterministic() {
        let w = wallet();
        let a1 = Deriver::new(&w).derive(0).unwrap();
        let a2 = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a1.address, a2.address);
    }

    #[test]
    fn different_indices() {
        let w = wallet();
        let d = Deriver::new(&w);
        assert_ne!(d.derive(0).unwrap().address, d.derive(1).unwrap().address);
    }

    #[test]
    fn osmosis_hrp() {
        let w = wallet();
        let a = Deriver::with_config(&w, "osmo", 118).derive(0).unwrap();
        assert!(a.address.starts_with("osmo1"));
    }

    #[test]
    fn same_coin_type_same_hash() {
        let w = wallet();
        let cosmos = Deriver::new(&w).derive(0).unwrap();
        let osmo = Deriver::with_config(&w, "osmo", 118).derive(0).unwrap();
        let (_, cd) = bech32::decode(&cosmos.address).unwrap();
        let (_, od) = bech32::decode(&osmo.address).unwrap();
        assert_eq!(cd, od);
    }

    #[test]
    fn terra_different_coin_type() {
        let w = wallet();
        let cosmos = Deriver::new(&w).derive(0).unwrap();
        let terra = Deriver::with_config(&w, "terra", 330).derive(0).unwrap();
        assert!(terra.address.starts_with("terra1"));
        assert_ne!(cosmos.address, terra.address);
    }

    #[test]
    fn derive_many_works() {
        let w = wallet();
        let accounts = Deriver::new(&w).derive_many(0, 3).unwrap();
        assert_eq!(accounts.len(), 3);
        assert_ne!(accounts[0].address, accounts[1].address);
    }

    #[test]
    fn derive_path_custom() {
        let w = wallet();
        let a = Deriver::new(&w).derive_path("m/44'/118'/0'/0/5").unwrap();
        assert!(a.address.starts_with("cosmos1"));
    }

    #[test]
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(MNEMONIC, Some("pass")).unwrap();
        assert_ne!(
            Deriver::new(&w1).derive(0).unwrap().address,
            Deriver::new(&w2).derive(0).unwrap().address,
        );
    }
}
