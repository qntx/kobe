//! Cosmos address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, format, string::String, vec::Vec};

pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::DeriveError;

/// Configuration for a Cosmos SDK chain.
///
/// Captures the bech32 human-readable prefix and BIP-44 coin type for a
/// specific chain. Common chains ship as associated constants
/// ([`COSMOS_HUB`](Self::COSMOS_HUB), [`OSMOSIS`](Self::OSMOSIS), …);
/// custom chains can be constructed via [`new`](Self::new).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ChainConfig {
    /// Bech32 human-readable part (`cosmos`, `osmo`, `terra`, …).
    pub hrp: Cow<'static, str>,
    /// BIP-44 coin type (`118` for Cosmos Hub, Osmosis; `330` for Terra; …).
    pub coin_type: u32,
}

impl ChainConfig {
    /// Cosmos Hub: `cosmos1…`, coin type `118`.
    pub const COSMOS_HUB: Self = Self {
        hrp: Cow::Borrowed("cosmos"),
        coin_type: 118,
    };

    /// Osmosis: `osmo1…`, coin type `118`.
    pub const OSMOSIS: Self = Self {
        hrp: Cow::Borrowed("osmo"),
        coin_type: 118,
    };

    /// Terra (classic / Luna 2.0): `terra1…`, coin type `330`.
    pub const TERRA: Self = Self {
        hrp: Cow::Borrowed("terra"),
        coin_type: 330,
    };

    /// Juno: `juno1…`, coin type `118`.
    pub const JUNO: Self = Self {
        hrp: Cow::Borrowed("juno"),
        coin_type: 118,
    };

    /// Secret Network: `secret1…`, coin type `529`.
    pub const SECRET: Self = Self {
        hrp: Cow::Borrowed("secret"),
        coin_type: 529,
    };

    /// Kava: `kava1…`, coin type `459`.
    pub const KAVA: Self = Self {
        hrp: Cow::Borrowed("kava"),
        coin_type: 459,
    };

    /// Construct a custom chain configuration.
    ///
    /// Accepts any `&'static str`, `String`, or `Cow<'static, str>` as
    /// the bech32 prefix.
    #[must_use]
    pub fn new(hrp: impl Into<Cow<'static, str>>, coin_type: u32) -> Self {
        Self {
            hrp: hrp.into(),
            coin_type,
        }
    }
}

impl Default for ChainConfig {
    #[inline]
    fn default() -> Self {
        Self::COSMOS_HUB
    }
}

/// Cosmos SDK address deriver.
///
/// Configurable bech32 prefix and BIP-44 coin type via [`ChainConfig`] for
/// any Cosmos SDK chain.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Wallet seed reference.
    wallet: &'a Wallet,
    /// Chain configuration (HRP + coin type).
    config: ChainConfig,
}

impl<'a> Deriver<'a> {
    /// Create a Cosmos Hub deriver (`cosmos1…`, coin type `118`).
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self::with_config(wallet, ChainConfig::COSMOS_HUB)
    }

    /// Create a deriver with an explicit [`ChainConfig`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use kobe_cosmos::{ChainConfig, Deriver};
    /// # let wallet: &kobe_primitives::Wallet = todo!();
    /// // Predefined chain:
    /// let d = Deriver::with_config(wallet, ChainConfig::OSMOSIS);
    /// // Custom chain:
    /// let d = Deriver::with_config(wallet, ChainConfig::new("stars", 118));
    /// ```
    #[must_use]
    pub const fn with_config(wallet: &'a Wallet, config: ChainConfig) -> Self {
        Self { wallet, config }
    }

    /// Return the active [`ChainConfig`].
    #[inline]
    #[must_use]
    pub const fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Derive at an arbitrary path (internal).
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
        let pubkey_bytes = key.compressed_pubkey();
        let address = encode_bech32_address(&self.config.hrp, &pubkey_bytes)?;

        Ok(DerivedAccount::new(
            String::from(path),
            key.private_key_bytes(),
            pubkey_bytes.to_vec(),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        let path = format!("m/44'/{}'/0'/0/{index}", self.config.coin_type);
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
#[allow(clippy::indexing_slicing, reason = "test assertions")]
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
        assert!(a.address().starts_with("cosmos1"));
    }

    #[test]
    fn deterministic() {
        let w = wallet();
        let a1 = Deriver::new(&w).derive(0).unwrap();
        let a2 = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a1.address(), a2.address());
    }

    #[test]
    fn different_indices() {
        let w = wallet();
        let d = Deriver::new(&w);
        assert_ne!(
            d.derive(0).unwrap().address(),
            d.derive(1).unwrap().address()
        );
    }

    #[test]
    fn osmosis_hrp() {
        let w = wallet();
        let a = Deriver::with_config(&w, ChainConfig::OSMOSIS)
            .derive(0)
            .unwrap();
        assert!(a.address().starts_with("osmo1"));
    }

    #[test]
    fn same_coin_type_same_hash() {
        let w = wallet();
        let cosmos = Deriver::new(&w).derive(0).unwrap();
        let osmo = Deriver::with_config(&w, ChainConfig::OSMOSIS)
            .derive(0)
            .unwrap();
        let (_, cd) = bech32::decode(cosmos.address()).unwrap();
        let (_, od) = bech32::decode(osmo.address()).unwrap();
        assert_eq!(cd, od);
    }

    #[test]
    fn terra_different_coin_type() {
        let w = wallet();
        let cosmos = Deriver::new(&w).derive(0).unwrap();
        let terra = Deriver::with_config(&w, ChainConfig::TERRA)
            .derive(0)
            .unwrap();
        assert!(terra.address().starts_with("terra1"));
        assert_ne!(cosmos.address(), terra.address());
    }

    #[test]
    fn custom_chain_config_from_string() {
        let w = wallet();
        let d = Deriver::with_config(&w, ChainConfig::new("stars", 118));
        assert!(d.derive(0).unwrap().address().starts_with("stars1"));
        assert_eq!(d.config().hrp, "stars");
        assert_eq!(d.config().coin_type, 118);
    }

    #[test]
    fn config_defaults_to_cosmos_hub() {
        assert_eq!(ChainConfig::default(), ChainConfig::COSMOS_HUB);
    }

    #[test]
    fn derive_many_works() {
        let w = wallet();
        let accounts = Deriver::new(&w).derive_many(0, 3).unwrap();
        assert_eq!(accounts.len(), 3);
        assert_ne!(accounts[0].address(), accounts[1].address());
    }

    #[test]
    fn derive_path_custom() {
        let w = wallet();
        let a = Deriver::new(&w).derive_path("m/44'/118'/0'/0/5").unwrap();
        assert!(a.address().starts_with("cosmos1"));
    }

    #[test]
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(MNEMONIC, Some("pass")).unwrap();
        assert_ne!(
            Deriver::new(&w1).derive(0).unwrap().address(),
            Deriver::new(&w2).derive(0).unwrap().address(),
        );
    }

    #[test]
    fn kat_cosmos_index0() {
        // Cross-verified with Python coincurve + SHA256 + RIPEMD160 + bech32
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address(), "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4");
    }
}
