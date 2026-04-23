//! Spark address derivation from a unified wallet.
//!
//! Implements the Spark Protocol (<https://docs.spark.money>) identity-key
//! derivation and Bech32m address encoding:
//!
//! - **Path**: `m/8797555'/{account}'/0'` — hardened BIP-32 secp256k1.
//!   The purpose `8797555` is a Spark-specific constant derived from
//!   `SHA-256("spark")`.
//! - **Address**: `bech32m(HRP, proto_wrap(compressed_pubkey))` where
//!   `proto_wrap` prepends the 2-byte pseudo-protobuf header `0x0a, 0x21`
//!   (field 1, length-delimited, 33 B). HRP depends on [`Network`]:
//!   - `spark` for mainnet
//!   - `sparkt` for testnet
//!   - `sparks` for signet
//!   - `sparkrt` for regtest
//!   - `sparkl` for local

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};

use bech32::{Bech32m, Hrp};
use kobe_primitives::{Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet};

/// Spark protocol networks, each bound to a distinct Bech32 HRP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Network {
    /// Main Spark network (`spark1…`).
    #[default]
    Mainnet,
    /// Testnet (`sparkt1…`).
    Testnet,
    /// Signet (`sparks1…`).
    Signet,
    /// Regtest (`sparkrt1…`).
    Regtest,
    /// Local development network (`sparkl1…`).
    Local,
}

impl Network {
    /// Bech32 human-readable prefix for this network.
    #[must_use]
    pub const fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "spark",
            Self::Testnet => "sparkt",
            Self::Signet => "sparks",
            Self::Regtest => "sparkrt",
            Self::Local => "sparkl",
        }
    }

    /// Human-readable display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
            Self::Local => "local",
        }
    }
}

/// Spark-specific BIP-32 purpose.
///
/// Matches the magic constant used by Spark SDKs; its decimal value
/// `8_797_555` equals the last three bytes of `SHA-256("spark")`
/// (`…863d73`) interpreted as a big-endian 24-bit integer, fitting BIP-43's
/// 31-bit purpose field.
///
/// Reference: <https://docs.spark.money/wallets/identity-key-derivation>.
pub const SPARK_PURPOSE: u32 = 8_797_555;

/// Pseudo-protobuf wire header prepended to the 33-byte compressed pubkey
/// before Bech32m encoding: field 1, wire type 2 (length-delimited).
const PROTO_TAG: u8 = 0x0a;
/// Length byte for a 33-byte compressed secp256k1 public key.
const COMPRESSED_PUBKEY_LEN: u8 = 33;

/// Spark address deriver from a unified wallet seed.
///
/// Derives Spark identity keys at path `m/8797555'/{account}'/0'` and
/// encodes the resulting compressed public key as a Bech32m address for
/// the configured [`Network`].
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
    /// Network that determines the Bech32m HRP.
    network: Network,
}

impl<'a> Deriver<'a> {
    /// Create a new mainnet Spark deriver.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self::with_network(wallet, Network::Mainnet)
    }

    /// Create a Spark deriver for the given network.
    #[must_use]
    pub const fn with_network(wallet: &'a Wallet, network: Network) -> Self {
        Self { wallet, network }
    }

    /// Return the configured network.
    #[inline]
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Derive a Spark identity account at the given account index.
    ///
    /// Uses the canonical Spark identity path
    /// `m/{SPARK_PURPOSE}'/{index}'/0'` — see
    /// <https://docs.spark.money/wallets/identity-key-derivation>.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or address encoding fails.
    #[inline]
    pub fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(&format!("m/{SPARK_PURPOSE}'/{index}'/0'"))
    }

    /// Derive at an arbitrary BIP-32 path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is malformed, derivation fails, or the
    /// resulting pubkey cannot be Bech32m-encoded.
    pub fn derive_at(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
        let pubkey_bytes = key.compressed_pubkey();
        let address = encode_spark_address(&pubkey_bytes, self.network)?;

        Ok(DerivedAccount::new(
            String::from(path),
            key.private_key_bytes(),
            DerivedPublicKey::Secp256k1Compressed(pubkey_bytes),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Account = DerivedAccount;
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        Deriver::derive(self, index)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(path)
    }
}

/// Encode a compressed secp256k1 public key as a Spark Bech32m address.
///
/// Wraps the 33-byte pubkey in a 2-byte pseudo-protobuf header (field 1,
/// wire type 2, length 33) and then Bech32m-encodes with the network's HRP.
///
/// # Errors
///
/// Returns [`DeriveError::AddressEncoding`] if HRP parsing or encoding fails
/// (practically never, as the HRPs are compile-time constants).
fn encode_spark_address(
    compressed_pubkey: &[u8; 33],
    network: Network,
) -> Result<String, DeriveError> {
    let mut payload = Vec::with_capacity(2 + compressed_pubkey.len());
    payload.push(PROTO_TAG);
    payload.push(COMPRESSED_PUBKEY_LEN);
    payload.extend_from_slice(compressed_pubkey);

    let hrp = Hrp::parse(network.hrp())
        .map_err(|e| DeriveError::AddressEncoding(format!("spark: invalid HRP: {e}")))?;
    bech32::encode::<Bech32m>(hrp, &payload)
        .map_err(|e| DeriveError::AddressEncoding(format!("spark bech32m: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    /// Cross-verified with the independent `ethanmarcuss/spark-address`
    /// Rust crate using its **published** mainnet test vector. This
    /// locks the low-level `encode_spark_address` byte pipeline
    /// (`0x0a || 0x21 || 33-byte pubkey` → Bech32m `spark1…`) against
    /// an external reference implementation that is not derived from
    /// kobe code.
    #[test]
    fn kat_encode_spark_address_matches_ethanmarcuss_reference() {
        let pubkey_hex = "02894808873b896e21d29856a6d7bb346fb13c019739adb9bf0b6a8b7e28da53da";
        let mut pubkey = [0u8; 33];
        hex::decode_to_slice(pubkey_hex, &mut pubkey).unwrap();
        let encoded = encode_spark_address(&pubkey, Network::Mainnet).unwrap();
        assert_eq!(
            encoded,
            "spark1pgss9z2gpzrnhztwy8ffs44x67angma38sqewwddhxlsk65t0c5d5576quly2j"
        );
    }

    /// End-to-end derivation + encoding KAT on the canonical
    /// `abandon…about` mnemonic at Spark identity key path
    /// `m/8797555'/{account}'/0'`. This test composes the spec-compliant
    /// encoder (verified above against ethanmarcuss) with kobe's BIP-32
    /// derivation, so any regression in the combined pipeline surfaces
    /// here.
    #[test]
    fn kat_spark_mainnet_abandon_index0() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/8797555'/0'/0'");
        assert_eq!(
            a.address(),
            "spark1pgssy6vty7krpze82ecm8j39gd35v35aqjjmhftc4culawsavkyh564uc6zmqs"
        );
    }

    /// Testnet Bech32m HRP `sparkt` must yield a different address on the
    /// same key material — confirms the HRP is the only difference while
    /// the underlying 33-byte compressed pubkey is unchanged.
    #[test]
    fn testnet_and_mainnet_share_keys_not_address() {
        let w = test_wallet();
        let main = Deriver::new(&w).derive(0).unwrap();
        let test = Deriver::with_network(&w, Network::Testnet)
            .derive(0)
            .unwrap();
        assert!(main.address().starts_with("spark1"));
        assert!(test.address().starts_with("sparkt1"));
        assert_eq!(main.private_key_bytes(), test.private_key_bytes());
        assert_eq!(main.public_key_bytes(), test.public_key_bytes());
        assert_ne!(main.address(), test.address());
    }

    /// Every non-mainnet `Network` variant must map to its spec-defined
    /// HRP, so `network()` matches the round-trip HRP of the emitted
    /// address. Regression test for the `Network → Hrp` table.
    #[test]
    fn every_network_roundtrips_hrp() {
        let w = test_wallet();
        for net in [
            Network::Mainnet,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
            Network::Local,
        ] {
            let a = Deriver::with_network(&w, net).derive(0).unwrap();
            let (hrp, _) = bech32::decode(a.address()).unwrap();
            assert_eq!(hrp.as_str(), net.hrp(), "HRP mismatch for {net:?}");
        }
    }
}
