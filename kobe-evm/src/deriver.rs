//! Ethereum address derivation from an HD wallet seed.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::str::FromStr;

use alloy_primitives::{Address, keccak256};
use bip32::{DerivationPath, XPrv};
use k256::ecdsa::SigningKey;
pub use kobe::DerivedAccount;
use kobe::{Derive, Wallet};
use zeroize::Zeroizing;

use crate::Error;

/// Derivation path styles for different wallet software.
///
/// MetaMask/Trezor, Ledger Live, and Ledger Legacy each use a different
/// BIP-44 path layout. See individual variant docs for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// `m/44'/60'/0'/0/{index}` — MetaMask, Trezor, Exodus (most common).
    #[default]
    Standard,
    /// `m/44'/60'/{index}'/0/0` — Ledger Live.
    LedgerLive,
    /// `m/44'/60'/0'/{index}` — Ledger Legacy / MEW / MyCrypto.
    LedgerLegacy,
}

impl DerivationStyle {
    /// Build the derivation path string for a given account index.
    #[must_use]
    pub fn path(self, index: u32) -> String {
        match self {
            Self::Standard => format!("m/44'/60'/0'/0/{index}"),
            Self::LedgerLive => format!("m/44'/60'/{index}'/0/0"),
            Self::LedgerLegacy => format!("m/44'/60'/0'/{index}"),
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "Standard (MetaMask/Trezor)",
            Self::LedgerLive => "Ledger Live",
            Self::LedgerLegacy => "Ledger Legacy",
        }
    }
}

impl fmt::Display for DerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for DerivationStyle {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" | "metamask" | "trezor" | "bip44" => Ok(Self::Standard),
            "ledger-live" | "ledgerlive" | "live" => Ok(Self::LedgerLive),
            "ledger-legacy" | "ledgerlegacy" | "legacy" | "mew" => Ok(Self::LedgerLegacy),
            _ => Err(Error::Derivation(format!("unknown derivation style: {s}"))),
        }
    }
}

/// Ethereum address deriver.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Wallet seed reference.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive with a specific [`DerivationStyle`].
    pub fn derive_with(&self, style: DerivationStyle, index: u32) -> Result<DerivedAccount, Error> {
        self.derive_at_path(&style.path(index))
    }

    /// Derive `count` accounts starting at `start` with a specific style.
    pub fn derive_many_with(
        &self,
        style: DerivationStyle,
        start: u32,
        count: u32,
    ) -> Result<Vec<DerivedAccount>, Error> {
        (start
            ..start
                .checked_add(count)
                .ok_or_else(|| Error::Derivation("index overflow".into()))?)
            .map(|i| self.derive_with(style, i))
            .collect()
    }

    /// Internal: derive at an arbitrary path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        let dp: DerivationPath = path
            .parse()
            .map_err(|e| Error::Derivation(format!("invalid path: {e}")))?;
        let xprv = XPrv::derive_from_path(self.wallet.seed(), &dp)
            .map_err(|e| Error::Derivation(format!("derivation failed: {e}")))?;

        let signing_key: &SigningKey = xprv.private_key();
        let verifying_key = signing_key.verifying_key();
        let uncompressed = verifying_key.to_encoded_point(false);
        let pubkey_bytes = uncompressed.as_bytes();

        let addr_hash = keccak256(&pubkey_bytes[1..]);
        let address = Address::from_slice(&addr_hash[12..]);

        Ok(DerivedAccount {
            path: path.to_string(),
            private_key: Zeroizing::new(hex::encode(signing_key.to_bytes())),
            public_key: hex::encode(pubkey_bytes),
            address: checksum_address(&address),
        })
    }
}

impl Derive for Deriver<'_> {
    type Error = Error;

    fn derive(&self, index: u32) -> Result<DerivedAccount, Error> {
        self.derive_with(DerivationStyle::Standard, index)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        self.derive_at_path(path)
    }

    fn overflow_error(&self) -> Error {
        Error::Derivation("index overflow".into())
    }
}

/// EIP-55 mixed-case checksum encoding.
fn checksum_address(address: &Address) -> String {
    let hex_addr = hex::encode(address.as_slice());
    let hash = keccak256(hex_addr.as_bytes());

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            let nibble = (hash[i / 2] >> (4 * (1 - i % 2))) & 0xf;
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
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
    fn derive_standard_address() {
        let w = wallet();
        let d = Deriver::new(&w);
        let a = d.derive(0).unwrap();
        assert!(a.address.starts_with("0x"));
        assert_eq!(a.address.len(), 42);
        assert_eq!(a.path, "m/44'/60'/0'/0/0");
    }

    #[test]
    fn deterministic() {
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        let b = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address, b.address);
    }

    #[test]
    fn different_indices() {
        let w = wallet();
        let d = Deriver::new(&w);
        assert_ne!(d.derive(0).unwrap().address, d.derive(1).unwrap().address);
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
    fn derivation_styles_produce_different_addresses() {
        let w = wallet();
        let d = Deriver::new(&w);
        let standard = d.derive_with(DerivationStyle::Standard, 1).unwrap();
        let live = d.derive_with(DerivationStyle::LedgerLive, 1).unwrap();
        let legacy = d.derive_with(DerivationStyle::LedgerLegacy, 1).unwrap();
        assert_ne!(standard.address, live.address);
        assert_ne!(standard.address, legacy.address);
        assert_ne!(live.address, legacy.address);
    }

    #[test]
    fn style_paths() {
        assert_eq!(DerivationStyle::Standard.path(0), "m/44'/60'/0'/0/0");
        assert_eq!(DerivationStyle::LedgerLive.path(1), "m/44'/60'/1'/0/0");
        assert_eq!(DerivationStyle::LedgerLegacy.path(2), "m/44'/60'/0'/2");
    }

    #[test]
    fn style_from_str() {
        assert_eq!(
            "standard".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "metamask".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "ledger-live".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::LedgerLive
        );
        assert_eq!(
            "legacy".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::LedgerLegacy
        );
        assert!("bad".parse::<DerivationStyle>().is_err());
    }

    #[test]
    fn derive_many_returns_correct_count() {
        let w = wallet();
        let d = Deriver::new(&w);
        let accounts = d.derive_many(0, 5).unwrap();
        assert_eq!(accounts.len(), 5);
        for (i, a) in accounts.iter().enumerate() {
            assert_eq!(a.path, format!("m/44'/60'/0'/0/{i}"));
        }
    }

    #[test]
    fn derive_path_custom() {
        let w = wallet();
        let d = Deriver::new(&w);
        let a = d.derive_path("m/44'/60'/0'/0/42").unwrap();
        assert_eq!(a.path, "m/44'/60'/0'/0/42");
        assert!(a.address.starts_with("0x"));
    }

    #[test]
    fn eip55_checksum_vectors() {
        let cases = [
            (
                "52908400098527886E0F7030069857D2E4169EE7",
                "0x52908400098527886E0F7030069857D2E4169EE7",
            ),
            (
                "de709f2102306220921060314715629080e2fb77",
                "0xde709f2102306220921060314715629080e2fb77",
            ),
            (
                "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
        ];
        for (hex_addr, expected) in cases {
            let addr = Address::from_slice(&hex::decode(hex_addr).unwrap());
            assert_eq!(checksum_address(&addr), expected);
        }
    }
}
