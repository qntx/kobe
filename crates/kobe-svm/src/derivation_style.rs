//! Solana derivation path styles.
//!
//! Different Solana wallets use slightly different BIP-44 path layouts
//! even though they all share SLIP-0010 Ed25519 as the underlying key
//! scheme. This module captures the three layouts seen in the wild and
//! implements the chain-agnostic
//! [`kobe_core::DerivationStyle`] trait so generic tooling (CLI
//! rendering, property tests, agent helpers) can treat Solana the same
//! way it treats EVM or TON.

use alloc::format;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use kobe_core::ParseDerivationStyleError;

/// Solana derivation-path layouts, indexed by the account index.
///
/// Variants are named after the path shape, not a vendor: the same layout
/// is shared by several wallets.
///
/// # Path specifications
///
/// | Variant        | Path layout                | Compatible wallets                                        |
/// | -------------- | -------------------------- | --------------------------------------------------------- |
/// | `Bip44Change`  | `m/44'/501'/{index}'/0'`   | Phantom, Solflare, Backpack, `MetaMask`, OKX, solana-keygen |
/// | `Bip44`        | `m/44'/501'/{index}'`      | Trust Wallet, Ledger Live, Keystone                       |
/// | `Legacy`       | `m/501'/{index}'/0'/0'`    | Sollet (**deprecated** — import only)                     |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// `m/44'/501'/{index}'/0'` — Phantom, Solflare, Backpack, `MetaMask`,
    /// OKX, solana-keygen.
    #[default]
    Bip44Change,
    /// `m/44'/501'/{index}'` — Trust Wallet, Ledger Live, Keystone.
    Bip44,
    /// `m/501'/{index}'/0'/0'` — Sollet (deprecated, kept for imports).
    Legacy,
}

/// Every variant of [`DerivationStyle`], returned by
/// [`kobe_core::DerivationStyle::all`].
const ALL_STYLES: &[DerivationStyle] = &[
    DerivationStyle::Bip44Change,
    DerivationStyle::Bip44,
    DerivationStyle::Legacy,
];

/// Tokens accepted by [`DerivationStyle::from_str`] (canonical + wallet aliases).
const ACCEPTED_TOKENS: &[&str] = &[
    "bip44-change",
    "phantom",
    "solflare",
    "backpack",
    "bip44",
    "trust",
    "trustwallet",
    "ledger",
    "ledger-live",
    "ledgerlive",
    "keystone",
    "legacy",
    "sollet",
    "old",
];

impl DerivationStyle {
    /// Short machine-readable identifier (e.g. `"bip44-change"`, `"legacy"`).
    ///
    /// Kept as an inherent `const fn` rather than a trait method because
    /// it is Solana-specific API used by the CLI; other chains do not all
    /// expose a short id.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Bip44Change => "bip44-change",
            Self::Bip44 => "bip44",
            Self::Legacy => "legacy",
        }
    }
}

impl kobe_core::DerivationStyle for DerivationStyle {
    fn path(self, index: u32) -> String {
        match self {
            Self::Bip44Change => format!("m/44'/501'/{index}'/0'"),
            Self::Bip44 => format!("m/44'/501'/{index}'"),
            Self::Legacy => format!("m/501'/{index}'/0'/0'"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Bip44Change => "BIP-44 change (Phantom/Solflare/Backpack)",
            Self::Bip44 => "BIP-44 (Trust Wallet/Ledger Live/Keystone)",
            Self::Legacy => "Legacy (Sollet, deprecated)",
        }
    }

    fn all() -> &'static [Self] {
        ALL_STYLES
    }
}

impl fmt::Display for DerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<Self as kobe_core::DerivationStyle>::name(*self))
    }
}

impl FromStr for DerivationStyle {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bip44-change" | "phantom" | "solflare" | "backpack" => Ok(Self::Bip44Change),
            "bip44" | "trust" | "trustwallet" | "ledger" | "ledger-live" | "ledgerlive"
            | "keystone" => Ok(Self::Bip44),
            "legacy" | "sollet" | "old" => Ok(Self::Legacy),
            _ => Err(ParseDerivationStyleError::new("solana", s, ACCEPTED_TOKENS)),
        }
    }
}

#[cfg(test)]
mod tests {
    use kobe_core::DerivationStyle as _;

    use super::*;

    #[test]
    fn test_bip44_change_paths() {
        let style = DerivationStyle::Bip44Change;
        assert_eq!(style.path(0), "m/44'/501'/0'/0'");
        assert_eq!(style.path(1), "m/44'/501'/1'/0'");
        assert_eq!(style.path(10), "m/44'/501'/10'/0'");
    }

    #[test]
    fn test_bip44_paths() {
        let style = DerivationStyle::Bip44;
        assert_eq!(style.path(0), "m/44'/501'/0'");
        assert_eq!(style.path(1), "m/44'/501'/1'");
        assert_eq!(style.path(10), "m/44'/501'/10'");
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
        // Bip44Change aliases
        assert_eq!(
            "bip44-change".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44Change
        );
        assert_eq!(
            "phantom".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44Change
        );
        assert_eq!(
            "solflare".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44Change
        );
        assert_eq!(
            "backpack".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44Change
        );

        // Bip44 aliases
        assert_eq!(
            "bip44".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44
        );
        assert_eq!(
            "trust".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44
        );
        assert_eq!(
            "ledger".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44
        );
        assert_eq!(
            "ledger-live".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44
        );
        assert_eq!(
            "keystone".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Bip44
        );

        // Legacy
        assert_eq!(
            "legacy".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Legacy
        );
        assert_eq!(
            "sollet".parse::<DerivationStyle>().unwrap(),
            DerivationStyle::Legacy
        );
    }

    #[test]
    fn test_from_str_invalid() {
        assert!("invalid".parse::<DerivationStyle>().is_err());
        // Removed pre-4.0 names must not resolve.
        assert!("standard".parse::<DerivationStyle>().is_err());
        assert!("live".parse::<DerivationStyle>().is_err());
        assert!("bip44change".parse::<DerivationStyle>().is_err());
        assert!("solana-keygen".parse::<DerivationStyle>().is_err());
        assert!("metamask".parse::<DerivationStyle>().is_err());
        assert!("okx".parse::<DerivationStyle>().is_err());
    }

    #[test]
    fn test_default() {
        assert_eq!(DerivationStyle::default(), DerivationStyle::Bip44Change);
    }
}
