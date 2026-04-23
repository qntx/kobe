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
mod tests {
    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> Wallet {
        Wallet::from_mnemonic(MNEMONIC, None).unwrap()
    }

    /// Known-answer test at BIP-44 path `m/44'/118'/0'/0/{i}` on Cosmos Hub.
    ///
    /// Address and private key are independently re-computed from
    /// `bip39 → bip32 → secp256k1 → ripemd160(sha256(compressed_pubkey))
    /// → bech32("cosmos", ...)` using `bip39`, `bip32`,
    /// `tiny-secp256k1`, `@cosmjs/crypto` and `@cosmjs/encoding` per the
    /// Cosmos SDK address spec at
    /// <https://docs.cosmos.network/main/build/spec/addresses/bech32>.
    #[test]
    fn kat_cosmos_hub_abandon_index0() {
        let a = Deriver::new(&wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/118'/0'/0/0");
        assert_eq!(a.address(), "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4");
        assert_eq!(
            a.private_key_hex().as_str(),
            "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104"
        );
    }

    #[test]
    fn kat_cosmos_hub_abandon_index1() {
        let a = Deriver::new(&wallet()).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/118'/0'/0/1");
        assert_eq!(a.address(), "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz");
        assert_eq!(
            a.private_key_hex().as_str(),
            "c9ba8e1818baf4ceb063420dcedc7a482056a1580e4dbe797af3484aff7b8651"
        );
    }

    /// Osmosis shares coin type `118` with Cosmos Hub, so changing only the
    /// HRP must produce a `bech32`-equivalent address with the same
    /// underlying 20-byte hash. Independently verified: Osmosis address
    /// below decodes to the same `hash160` as the Cosmos Hub KAT above.
    #[test]
    fn kat_osmosis_abandon_index0() {
        let a = Deriver::with_config(&wallet(), ChainConfig::OSMOSIS)
            .derive(0)
            .unwrap();
        assert_eq!(a.address(), "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8");
    }

    /// Changing only the HRP must keep the 20-byte program (same
    /// `hash160(pubkey)`) but flip the human-readable prefix.
    #[test]
    fn hrp_change_preserves_program_hash() {
        let w = wallet();
        let cosmos = Deriver::new(&w).derive(0).unwrap();
        let osmo = Deriver::with_config(&w, ChainConfig::OSMOSIS)
            .derive(0)
            .unwrap();
        let (cosmos_hrp, cosmos_data) = bech32::decode(cosmos.address()).unwrap();
        let (osmo_hrp, osmo_data) = bech32::decode(osmo.address()).unwrap();
        assert_eq!(cosmos_hrp.as_str(), "cosmos");
        assert_eq!(osmo_hrp.as_str(), "osmo");
        assert_eq!(cosmos_data, osmo_data);
    }

    /// Terra uses SLIP-44 coin type `330` (not `118`), so it must derive a
    /// different private key and therefore a different 20-byte hash.
    #[test]
    fn terra_uses_distinct_coin_type() {
        let w = wallet();
        let cosmos = Deriver::new(&w).derive(0).unwrap();
        let terra = Deriver::with_config(&w, ChainConfig::TERRA)
            .derive(0)
            .unwrap();
        let (_, cosmos_data) = bech32::decode(cosmos.address()).unwrap();
        let (_, terra_data) = bech32::decode(terra.address()).unwrap();
        assert_ne!(cosmos_data, terra_data);
        assert!(terra.address().starts_with("terra1"));
    }

    /// Custom `ChainConfig` must honour the caller's HRP and coin type
    /// verbatim and expose them via `config()`.
    #[test]
    fn custom_chain_config_roundtrips() {
        let w = wallet();
        let d = Deriver::with_config(&w, ChainConfig::new("stars", 118));
        assert_eq!(d.config().hrp.as_ref(), "stars");
        assert_eq!(d.config().coin_type, 118);
        // `stars` shares coin type 118 with Cosmos Hub, so the 20-byte
        // hash must match the Cosmos Hub KAT.
        let stars = d.derive(0).unwrap();
        let (_, stars_data) = bech32::decode(stars.address()).unwrap();
        let cosmos = Deriver::new(&w).derive(0).unwrap();
        let (_, cosmos_data) = bech32::decode(cosmos.address()).unwrap();
        assert_eq!(stars_data, cosmos_data);
    }

    #[test]
    fn default_config_is_cosmos_hub() {
        assert_eq!(ChainConfig::default(), ChainConfig::COSMOS_HUB);
    }

    /// `derive_many` must agree with scalar `derive` for every index.
    #[test]
    fn derive_many_matches_individual() {
        let w = wallet();
        let d = Deriver::new(&w);
        let batch = d.derive_many(0, 3).unwrap();
        let single: Vec<_> = (0..3).map(|i| d.derive(i).unwrap()).collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
        }
    }

    #[test]
    fn passphrase_changes_derivation() {
        let w = Wallet::from_mnemonic(MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            Deriver::new(&wallet()).derive(0).unwrap().address(),
            Deriver::new(&w).derive(0).unwrap().address(),
        );
    }
}
