//! Derivation path styles for different Solana wallet software.
//!
//! Different wallet software (Phantom, Ledger, Trust Wallet) use different
//! BIP-44 derivation paths. This module provides predefined styles for compatibility.

use alloc::{format, string::String};
use core::fmt;
use core::str::FromStr;

/// Solana derivation path styles for different wallet software.
///
/// Different hardware and software wallets use different derivation paths
/// even though they all follow BIP-44 principles. This enum provides
/// the most common styles for maximum compatibility.
///
/// # Path Specifications (as of 2026)
///
/// - **Standard (Phantom/Backpack)**: `m/44'/501'/{index}'/0'`
/// - **Trust**: `m/44'/501'/{index}'`
/// - **Ledger Live**: `m/44'/501'/{index}'/0'/0'`
/// - **Legacy**: `m/501'/{index}'/0/0` (deprecated)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// Standard BIP44-Change path used by Phantom and Backpack.
    ///
    /// Path format: `m/44'/501'/{index}'/0'`
    ///
    /// This is the most widely adopted standard where:
    /// - Purpose: 44' (BIP-44)
    /// - Coin type: 501' (Solana)
    /// - Account: variable (hardened)
    /// - Change: 0' (hardened, fixed)
    ///
    /// Used by: Phantom, Backpack, Solflare, Trezor, Exodus, Magic Eden
    #[default]
    Standard,

    /// Trust Wallet / Ledger native derivation path.
    ///
    /// Path format: `m/44'/501'/{index}'`
    ///
    /// BIP-44 path without change component:
    /// - Purpose: 44' (BIP-44)
    /// - Coin type: 501' (Solana)
    /// - Account: variable (hardened)
    ///
    /// Used by: Trust Wallet, Ledger (native), Keystone
    Trust,

    /// Ledger Live derivation path (account-based).
    ///
    /// Path format: `m/44'/501'/{index}'/0'/0'`
    ///
    /// Used by Ledger Live application:
    /// - Purpose: 44' (BIP-44)
    /// - Coin type: 501' (Solana)
    /// - Account: variable (hardened)
    /// - Change: 0' (hardened, fixed)
    /// - Address index: 0' (hardened, fixed)
    LedgerLive,

    /// Legacy derivation path (deprecated).
    ///
    /// Path format: `m/501'/{index}'/0/0`
    ///
    /// Used by older versions of Phantom and Sollet.
    /// Only use for recovering old wallets.
    #[deprecated(
        note = "Use Standard style for new wallets. Legacy is only for recovering old Phantom/Sollet wallets."
    )]
    Legacy,
}

impl DerivationStyle {
    /// Generate the derivation path string for a given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The account index to derive
    ///
    /// # Returns
    ///
    /// A BIP-32 derivation path string.
    #[must_use]
    #[allow(deprecated)]
    pub fn path(self, index: u32) -> String {
        match self {
            Self::Standard => format!("m/44'/501'/{index}'/0'"),
            Self::Trust => format!("m/44'/501'/{index}'"),
            Self::LedgerLive => format!("m/44'/501'/{index}'/0'/0'"),
            Self::Legacy => format!("m/501'/{index}'/0/0"),
        }
    }

    /// Get the human-readable name of this derivation style.
    #[must_use]
    #[allow(deprecated)]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "Standard (Phantom/Backpack)",
            Self::Trust => "Trust (Ledger/Keystone)",
            Self::LedgerLive => "Ledger Live",
            Self::Legacy => "Legacy (deprecated)",
        }
    }

    /// Get a short identifier for CLI usage.
    #[must_use]
    #[allow(deprecated)]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Trust => "trust",
            Self::LedgerLive => "ledger-live",
            Self::Legacy => "legacy",
        }
    }

    /// Get all available derivation styles.
    #[must_use]
    #[allow(deprecated)]
    pub const fn all() -> &'static [Self] {
        &[Self::Standard, Self::Trust, Self::LedgerLive, Self::Legacy]
    }
}

impl fmt::Display for DerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Error returned when parsing an invalid derivation style string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDerivationStyleError(pub(crate) String);

impl fmt::Display for ParseDerivationStyleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid derivation style '{}', expected one of: standard, trust, ledger-live, legacy",
            self.0
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseDerivationStyleError {}

#[allow(deprecated)]
impl FromStr for DerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            // Standard (Phantom, Backpack, etc.)
            "standard" | "phantom" | "backpack" | "solflare" | "trezor" => Ok(Self::Standard),
            // Trust (Ledger native, Keystone)
            "trust" | "trustwallet" | "ledger" | "ledger-native" | "ledgernative" | "keystone" => {
                Ok(Self::Trust)
            }
            // Ledger Live
            "ledger-live" | "ledgerlive" | "live" => Ok(Self::LedgerLive),
            // Legacy (deprecated)
            "legacy" | "old" | "sollet" => Ok(Self::Legacy),
            _ => Err(ParseDerivationStyleError(s.into())),
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_paths() {
        let style = DerivationStyle::Standard;
        assert_eq!(style.path(0), "m/44'/501'/0'/0'");
        assert_eq!(style.path(1), "m/44'/501'/1'/0'");
        assert_eq!(style.path(10), "m/44'/501'/10'/0'");
    }

    #[test]
    fn test_trust_paths() {
        let style = DerivationStyle::Trust;
        assert_eq!(style.path(0), "m/44'/501'/0'");
        assert_eq!(style.path(1), "m/44'/501'/1'");
        assert_eq!(style.path(10), "m/44'/501'/10'");
    }

    #[test]
    fn test_ledger_live_paths() {
        let style = DerivationStyle::LedgerLive;
        assert_eq!(style.path(0), "m/44'/501'/0'/0'/0'");
        assert_eq!(style.path(1), "m/44'/501'/1'/0'/0'");
        assert_eq!(style.path(10), "m/44'/501'/10'/0'/0'");
    }

    #[test]
    fn test_legacy_paths() {
        let style = DerivationStyle::Legacy;
        assert_eq!(style.path(0), "m/501'/0'/0/0");
        assert_eq!(style.path(1), "m/501'/1'/0/0");
        assert_eq!(style.path(10), "m/501'/10'/0/0");
    }

    #[test]
    fn test_from_str() {
        // Standard aliases
        assert_eq!(
            "standard".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "phantom".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );
        assert_eq!(
            "backpack".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Standard
        );

        // Trust aliases
        assert_eq!(
            "trust".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Trust
        );
        assert_eq!(
            "ledger".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Trust
        );
        assert_eq!(
            "keystone".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Trust
        );

        // Ledger Live
        assert_eq!(
            "ledger-live".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::LedgerLive
        );

        // Legacy
        assert_eq!(
            "legacy".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Legacy
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
