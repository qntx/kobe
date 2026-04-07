//! Cosmos address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};

pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::DeriveError;

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
    /// Create a Cosmos Hub deriver (`cosmos1...`, `coin_type` 118).
    #[must_use]
    pub fn new(wallet: &'a Wallet) -> Self {
        Self {
            wallet,
            hrp: "cosmos".to_owned(),
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
            hrp: hrp.to_owned(),
            coin_type,
        }
    }

    /// Derive at an arbitrary path (internal).
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = kobe_primitives::bip32::DerivedSecp256k1Key::derive(self.wallet.seed(), path)?;
        let pubkey_bytes = key.compressed_pubkey();
        let address = encode_bech32_address(&self.hrp, &pubkey_bytes)?;

        Ok(DerivedAccount::new(
            path.to_owned(),
            key.private_key_hex(),
            key.compressed_pubkey_hex(),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        let path = format!("m/44'/{}'/0'/0/{index}", self.coin_type);
        self.derive_at_path(&path)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
}

/// Hash160: SHA-256 then RIPEMD-160.
fn hash160(data: &[u8]) -> Vec<u8> {
    Ripemd160::digest(Sha256::digest(data)).to_vec()
}

/// Encode a compressed public key as a bech32 Cosmos address.
fn encode_bech32_address(hrp: &str, compressed_pubkey: &[u8]) -> Result<String, DeriveError> {
    let hash = hash160(compressed_pubkey);
    let hrp_parsed = bech32::Hrp::parse(hrp)
        .map_err(|e| DeriveError::AddressEncoding(format!("invalid HRP: {e}")))?;
    bech32::encode::<bech32::Bech32>(hrp_parsed, &hash)
        .map_err(|e| DeriveError::AddressEncoding(format!("bech32 encoding failed: {e}")))
}

#[cfg(test)]
mod tests {
    use kobe_primitives::DeriveExt;

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

    #[test]
    fn kat_cosmos_index0() {
        // Cross-verified with Python coincurve + SHA256 + RIPEMD160 + bech32
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address, "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4");
    }
}
