//! Solana derivation path styles.
//!
//! Different Solana wallets use slightly different BIP-44 path layouts
//! even though they all share SLIP-0010 Ed25519 as the underlying key
//! scheme. This module captures the four widely-supported layouts and
//! implements the chain-agnostic
//! [`kobe_primitives::DerivationStyle`] trait so generic tooling (CLI
//! rendering, property tests, agent helpers) can treat Solana the same
//! way it treats EVM or TON.

use alloc::format;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use kobe_primitives::ParseDerivationStyleError;

/// Solana derivation-path layouts, indexed by the account index.
///
/// # Path specifications
///
/// | Variant        | Path layout                     | Compatible wallets                        |
/// | -------------- | ------------------------------- | ----------------------------------------- |
/// | `Standard`     | `m/44'/501'/{index}'/0'`        | Phantom, Backpack, Solflare, Magic Eden   |
/// | `Trust`        | `m/44'/501'/{index}'`           | Trust Wallet, Ledger (native), Keystone   |
/// | `LedgerLive`   | `m/44'/501'/{index}'/0'/0'`     | Ledger Live                               |
/// | `Legacy`       | `m/501'/{index}'/0'/0'`         | Older Phantom, Sollet (**deprecated**)    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// `m/44'/501'/{index}'/0'` — Phantom, Backpack, Solflare, …
    #[default]
    Standard,
    /// `m/44'/501'/{index}'` — Trust Wallet, Ledger (native), Keystone.
    Trust,
    /// `m/44'/501'/{index}'/0'/0'` — Ledger Live.
    LedgerLive,
    /// `m/501'/{index}'/0'/0'` — legacy Phantom / Sollet (deprecated).
    Legacy,
}

/// Every variant of [`DerivationStyle`], returned by
/// [`kobe_primitives::DerivationStyle::all`].
const ALL_STYLES: &[DerivationStyle] = &[
    DerivationStyle::Standard,
    DerivationStyle::Trust,
    DerivationStyle::LedgerLive,
    DerivationStyle::Legacy,
];

/// Tokens accepted by [`DerivationStyle::from_str`] (canonical + wallet aliases).
const ACCEPTED_TOKENS: &[&str] = &[
    "standard",
    "phantom",
    "backpack",
    "solflare",
    "trezor",
    "trust",
    "trustwallet",
    "ledger",
    "ledger-native",
    "ledgernative",
    "keystone",
    "ledger-live",
    "ledgerlive",
    "live",
    "legacy",
    "old",
    "sollet",
];

impl DerivationStyle {
    /// Short machine-readable identifier (e.g. `"standard"`, `"ledger-live"`).
    ///
    /// Kept as an inherent `const fn` rather than a trait method because
    /// it is Solana-specific API used by the CLI for backwards compatibility;
    /// other chains do not all expose a short id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Trust => "trust",
            Self::LedgerLive => "ledger-live",
            Self::Legacy => "legacy",
        }
    }
}

impl kobe_primitives::DerivationStyle for DerivationStyle {
    fn path(self, index: u32) -> String {
        match self {
            Self::Standard => format!("m/44'/501'/{index}'/0'"),
            Self::Trust => format!("m/44'/501'/{index}'"),
            Self::LedgerLive => format!("m/44'/501'/{index}'/0'/0'"),
            Self::Legacy => format!("m/501'/{index}'/0'/0'"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Standard => "Standard (Phantom/Backpack)",
            Self::Trust => "Trust (Ledger/Keystone)",
            Self::LedgerLive => "Ledger Live",
            Self::Legacy => "Legacy (deprecated)",
        }
    }

    fn all() -> &'static [Self] {
        ALL_STYLES
    }
}

impl fmt::Display for DerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<Self as kobe_primitives::DerivationStyle>::name(*self))
    }
}

impl FromStr for DerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" | "phantom" | "backpack" | "solflare" | "trezor" => Ok(Self::Standard),
            "trust" | "trustwallet" | "ledger" | "ledger-native" | "ledgernative" | "keystone" => {
                Ok(Self::Trust)
            }
            "ledger-live" | "ledgerlive" | "live" => Ok(Self::LedgerLive),
            "legacy" | "old" | "sollet" => Ok(Self::Legacy),
            _ => Err(ParseDerivationStyleError::new("solana", s, ACCEPTED_TOKENS)),
        }
    }
}

#[cfg(test)]
mod tests {
    use kobe_primitives::DerivationStyle as _;

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
        assert_eq!(style.path(0), "m/501'/0'/0'/0'");
        assert_eq!(style.path(1), "m/501'/1'/0'/0'");
        assert_eq!(style.path(10), "m/501'/10'/0'/0'");
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
