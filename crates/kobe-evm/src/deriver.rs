//! Ethereum address derivation from an HD wallet seed.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use alloy_primitives::{Address, keccak256};
pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet};

use crate::DeriveError;

/// Derivation path styles for different wallet software.
///
/// MetaMask/Trezor, Ledger Live, and Ledger Legacy each use a different
/// BIP-44 path layout. See individual variant docs for details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// `m/44'/60'/0'/0/{index}` — `MetaMask`, Trezor, Exodus (most common).
    #[default]
    Standard,
    /// `m/44'/60'/{index}'/0/0` — Ledger Live.
    LedgerLive,
    /// `m/44'/60'/0'/{index}` — Ledger Legacy / MEW / `MyCrypto`.
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
    type Err = DeriveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" | "metamask" | "trezor" | "bip44" => Ok(Self::Standard),
            "ledger-live" | "ledgerlive" | "live" => Ok(Self::LedgerLive),
            "ledger-legacy" | "ledgerlegacy" | "legacy" | "mew" => Ok(Self::LedgerLegacy),
            _ => Err(DeriveError::UnknownDerivationStyle(s.into())),
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
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_with(
        &self,
        style: DerivationStyle,
        index: u32,
    ) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(&style.path(index))
    }

    /// Derive `count` accounts starting at `start` with a specific style.
    ///
    /// # Errors
    ///
    /// Returns an error if any individual derivation fails or `start + count` overflows.
    pub fn derive_many_with(
        &self,
        style: DerivationStyle,
        start: u32,
        count: u32,
    ) -> Result<Vec<DerivedAccount>, DeriveError> {
        let end = start.checked_add(count).ok_or_else(|| {
            kobe_primitives::DeriveError::Input(String::from(
                "derive_many: start + count overflows u32",
            ))
        })?;
        (start..end).map(|i| self.derive_with(style, i)).collect()
    }

    /// Internal: derive at an arbitrary path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = kobe_primitives::bip32::DerivedSecp256k1Key::derive(self.wallet.seed(), path)?;
        let uncompressed = key.uncompressed_pubkey();

        let addr_hash = keccak256(&uncompressed[1..]);
        let (_, addr_bytes) = addr_hash.split_at(12);
        let address = Address::from_slice(addr_bytes);

        Ok(DerivedAccount::new(
            String::from(path),
            key.private_key_bytes(),
            uncompressed.to_vec(),
            address.to_checksum(None),
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_with(DerivationStyle::Standard, index)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
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
    fn derive_standard_address() {
        let w = wallet();
        let d = Deriver::new(&w);
        let a = d.derive(0).unwrap();
        assert!(a.address().starts_with("0x"));
        assert_eq!(a.address().len(), 42);
        assert_eq!(a.path(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn deterministic() {
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        let b = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address(), b.address());
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
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(MNEMONIC, Some("pass")).unwrap();
        assert_ne!(
            Deriver::new(&w1).derive(0).unwrap().address(),
            Deriver::new(&w2).derive(0).unwrap().address(),
        );
    }

    #[test]
    fn derivation_styles_produce_different_addresses() {
        let w = wallet();
        let d = Deriver::new(&w);
        let standard = d.derive_with(DerivationStyle::Standard, 1).unwrap();
        let live = d.derive_with(DerivationStyle::LedgerLive, 1).unwrap();
        let legacy = d.derive_with(DerivationStyle::LedgerLegacy, 1).unwrap();
        assert_ne!(standard.address(), live.address());
        assert_ne!(standard.address(), legacy.address());
        assert_ne!(live.address(), legacy.address());
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
            assert_eq!(a.path(), format!("m/44'/60'/0'/0/{i}"));
        }
    }

    #[test]
    fn derive_path_custom() {
        let w = wallet();
        let d = Deriver::new(&w);
        let a = d.derive_path("m/44'/60'/0'/0/42").unwrap();
        assert_eq!(a.path(), "m/44'/60'/0'/0/42");
        assert!(a.address().starts_with("0x"));
    }

    #[test]
    fn eip55_checksum_via_alloy() {
        let addr: Address = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
            .parse()
            .unwrap();
        assert_eq!(
            addr.to_checksum(None),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    #[test]
    fn kat_evm_standard_index0() {
        // Cross-verified with Python coincurve + keccak256 + EIP-55
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.address(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(
            a.private_key_hex().as_str(),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
    }

    #[test]
    fn kat_evm_standard_index1() {
        let w = wallet();
        let a = Deriver::new(&w).derive(1).unwrap();
        assert_eq!(a.address(), "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0");
    }
}
