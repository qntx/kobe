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
pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet};

use crate::DeriveError;

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
        self.derive_at_path(&format!("m/{SPARK_PURPOSE}'/{index}'/0'"))
    }

    /// Derive at an arbitrary BIP-32 path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is malformed, derivation fails, or the
    /// resulting pubkey cannot be Bech32m-encoded.
    pub fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
        let pubkey_bytes = key.compressed_pubkey();
        let address = encode_spark_address(&pubkey_bytes, self.network)?;

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
        Deriver::derive(self, index)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
}

/// Encode a compressed secp256k1 public key as a Spark Bech32m address.
///
/// Wraps the 33-byte pubkey in a 2-byte pseudo-protobuf header (field 1,
/// wire type 2, length 33) and then Bech32m-encodes with the network's HRP.
///
/// # Errors
///
/// Returns [`DeriveError::Bech32`] if HRP parsing or encoding fails
/// (practically never, as the HRPs are compile-time constants).
fn encode_spark_address(
    compressed_pubkey: &[u8; 33],
    network: Network,
) -> Result<String, DeriveError> {
    let mut payload = Vec::with_capacity(2 + compressed_pubkey.len());
    payload.push(PROTO_TAG);
    payload.push(COMPRESSED_PUBKEY_LEN);
    payload.extend_from_slice(compressed_pubkey);

    let hrp =
        Hrp::parse(network.hrp()).map_err(|e| DeriveError::Bech32(format!("invalid HRP: {e}")))?;
    bech32::encode::<Bech32m>(hrp, &payload)
        .map_err(|e| DeriveError::Bech32(format!("encoding failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    #[test]
    fn derive_starts_with_spark1() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert!(
            derived.address().starts_with("spark1"),
            "mainnet address should start with spark1, got: {}",
            derived.address()
        );
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path(), "m/8797555'/0'/0'");
    }

    #[test]
    fn deterministic() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_eq!(a1.address(), a2.address());
    }

    #[test]
    fn different_account_numbers_differ() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        assert_ne!(
            d.derive(0).unwrap().address(),
            d.derive(1).unwrap().address()
        );
    }

    #[test]
    fn testnet_prefix() {
        let wallet = test_wallet();
        let a = Deriver::with_network(&wallet, Network::Testnet)
            .derive(0)
            .unwrap();
        assert!(
            a.address().starts_with("sparkt1"),
            "testnet address should start with sparkt1, got: {}",
            a.address()
        );
    }

    #[test]
    fn regtest_prefix() {
        let wallet = test_wallet();
        let a = Deriver::with_network(&wallet, Network::Regtest)
            .derive(0)
            .unwrap();
        assert!(a.address().starts_with("sparkrt1"));
    }

    #[test]
    fn network_accessor_returns_configured_value() {
        let wallet = test_wallet();
        assert_eq!(
            Deriver::with_network(&wallet, Network::Signet).network(),
            Network::Signet
        );
    }

    #[test]
    fn mainnet_and_testnet_addresses_differ() {
        let wallet = test_wallet();
        let main = Deriver::with_network(&wallet, Network::Mainnet)
            .derive(0)
            .unwrap();
        let test = Deriver::with_network(&wallet, Network::Testnet)
            .derive(0)
            .unwrap();
        assert_ne!(main.address(), test.address());
        // But the underlying private key is identical — the HRP only changes
        // the wire format of the address.
        assert_eq!(main.private_key_bytes(), test.private_key_bytes());
    }

    #[test]
    fn public_key_is_33_byte_compressed() {
        let wallet = test_wallet();
        let a = Deriver::new(&wallet).derive(0).unwrap();
        let pk = a.public_key_bytes();
        assert_eq!(pk.len(), 33);
        let prefix = pk.first().copied().expect("33-byte pubkey");
        assert!(
            prefix == 0x02 || prefix == 0x03,
            "compressed pubkey prefix must be 0x02 or 0x03"
        );
    }

    /// Cross-verified with the independent `spark-address` crate
    /// (ethanmarcuss/spark-address) using its published mainnet test vector.
    #[test]
    fn kat_encode_spark_address_matches_reference_vector() {
        let pubkey_hex = "02894808873b896e21d29856a6d7bb346fb13c019739adb9bf0b6a8b7e28da53da";
        let mut pubkey = [0u8; 33];
        hex::decode_to_slice(pubkey_hex, &mut pubkey).unwrap();
        let encoded = encode_spark_address(&pubkey, Network::Mainnet).unwrap();
        assert_eq!(
            encoded,
            "spark1pgss9z2gpzrnhztwy8ffs44x67angma38sqewwddhxlsk65t0c5d5576quly2j"
        );
    }

    /// End-to-end derivation + encoding regression lock for the canonical
    /// BIP-39 "abandon…about" mnemonic at account 0.
    ///
    /// Locked against kobe's BIP-32 secp256k1 derivation composed with the
    /// `encode_spark_address` implementation above (the latter is
    /// cross-verified against the independent `ethanmarcuss/spark-address`
    /// reference).
    #[test]
    fn kat_spark_abandon_mnemonic_index0() {
        let wallet = test_wallet();
        let a = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(a.path(), "m/8797555'/0'/0'");
        assert_eq!(
            a.address(),
            "spark1pgssy6vty7krpze82ecm8j39gd35v35aqjjmhftc4culawsavkyh564uc6zmqs"
        );
    }
}
