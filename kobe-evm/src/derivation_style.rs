//! Derivation path styles for different wallet software.
//!
//! Different wallet software (`MetaMask`, Ledger, Trezor) use different BIP-44
//! derivation paths. This module provides predefined styles for compatibility.

use alloc::{format, string::String};
use core::fmt;
use core::str::FromStr;

/// Ethereum derivation path styles for different wallet software.
///
/// Different hardware and software wallets use different derivation paths
/// even though they all follow BIP-44 principles. This enum provides
/// the most common styles for maximum compatibility.
///
/// # Path Specifications (as of 2024)
///
/// - **MetaMask/Trezor**: Standard BIP-44 `m/44'/60'/0'/0/{index}`
/// - **Ledger Live**: Account-based `m/44'/60'/{index}'/0/0`
/// - **Ledger Legacy**: MEW/MyCrypto compatible `m/44'/60'/0'/{index}`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// Standard BIP-44 path used by `MetaMask` and Trezor.
    ///
    /// Path format: `m/44'/60'/0'/0/{index}`
    ///
    /// This is the most widely adopted standard where:
    /// - Purpose: 44' (BIP-44)
    /// - Coin type: 60' (Ethereum)
    /// - Account: 0' (fixed)
    /// - Change: 0 (external)
    /// - Address index: variable
    #[default]
    Standard,

    /// Ledger Live derivation path.
    ///
    /// Path format: `m/44'/60'/{index}'/0/0`
    ///
    /// Ledger Live treats each index as a separate account:
    /// - Purpose: 44' (BIP-44)
    /// - Coin type: 60' (Ethereum)
    /// - Account: variable (hardened)
    /// - Change: 0 (external)
    /// - Address index: 0 (fixed)
    LedgerLive,

    /// Ledger Legacy derivation path (MEW/MyCrypto compatible).
    ///
    /// Path format: `m/44'/60'/0'/{index}`
    ///
    /// Used by older Ledger Chrome app and compatible with MEW/MyCrypto:
    /// - Purpose: 44' (BIP-44)
    /// - Coin type: 60' (Ethereum)
    /// - Account: 0' (fixed)
    /// - Address index: variable (at 4th level, non-hardened)
    LedgerLegacy,
}

impl DerivationStyle {
    /// Generate the derivation path string for a given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The address/account index to derive
    ///
    /// # Returns
    ///
    /// A BIP-32 derivation path string.
    #[must_use]
    pub fn path(self, index: u32) -> String {
        match self {
            Self::Standard => format!("m/44'/60'/0'/0/{index}"),
            Self::LedgerLive => format!("m/44'/60'/{index}'/0/0"),
            Self::LedgerLegacy => format!("m/44'/60'/0'/{index}"),
        }
    }

    /// Get the human-readable name of this derivation style.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "Standard (MetaMask/Trezor)",
            Self::LedgerLive => "Ledger Live",
            Self::LedgerLegacy => "Ledger Legacy (MEW/MyCrypto)",
        }
    }

    /// Get a short identifier for CLI usage.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::LedgerLive => "ledger-live",
            Self::LedgerLegacy => "ledger-legacy",
        }
    }

    /// Get all available derivation styles.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Standard, Self::LedgerLive, Self::LedgerLegacy]
    }
}

impl fmt::Display for DerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for DerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" | "metamask" | "trezor" | "bip44" => Ok(Self::Standard),
            "ledger-live" | "ledgerlive" | "live" => Ok(Self::LedgerLive),
            "ledger-legacy" | "ledgerlegacy" | "legacy" | "mew" | "mycrypto" => {
                Ok(Self::LedgerLegacy)
            }
            _ => Err(ParseDerivationStyleError(s.into())),
        }
    }
}

/// Error returned when parsing an invalid derivation style string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDerivationStyleError(pub(crate) String);

impl fmt::Display for ParseDerivationStyleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid derivation style '{}', expected one of: standard, ledger-live, ledger-legacy",
            self.0
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseDerivationStyleError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_paths() {
        let style = DerivationStyle::Standard;
        assert_eq!(style.path(0), "m/44'/60'/0'/0/0");
        assert_eq!(style.path(1), "m/44'/60'/0'/0/1");
        assert_eq!(style.path(10), "m/44'/60'/0'/0/10");
    }

    #[test]
    fn test_ledger_live_paths() {
        let style = DerivationStyle::LedgerLive;
        assert_eq!(style.path(0), "m/44'/60'/0'/0/0");
        assert_eq!(style.path(1), "m/44'/60'/1'/0/0");
        assert_eq!(style.path(10), "m/44'/60'/10'/0/0");
    }

    #[test]
    fn test_ledger_legacy_paths() {
        let style = DerivationStyle::LedgerLegacy;
        assert_eq!(style.path(0), "m/44'/60'/0'/0");
        assert_eq!(style.path(1), "m/44'/60'/0'/1");
        assert_eq!(style.path(10), "m/44'/60'/0'/10");
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            "standard".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "metamask".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "trezor".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "ledger-live".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::LedgerLive
        );
        assert_eq!(
            "ledger-legacy".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::LedgerLegacy
        );
        assert_eq!(
            "mew".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::LedgerLegacy
        );
    }

    #[test]
    fn test_from_str_invalid() {
        assert!("invalid".parse::<DerivationStyle>().is_err());
    }

    #[test]
    fn test_default() {
        assert_eq!(DerivationStyle::default(), DerivationStyle::Standard);
    }
}
