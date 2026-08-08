//! TON derivation path styles.

use alloc::format;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use kobe_primitives::ParseDerivationStyleError;

/// TON derivation path styles.
///
/// Tonkeeper and most software wallets use `m/44'/607'/{index}'`.
/// Ledger Live uses `m/44'/607'/{index}'/0'/0'`.
///
/// The chain-agnostic contract (path / name / all / `FromStr`) is defined
/// by the [`kobe_primitives::DerivationStyle`] trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// `m/44'/607'/{index}'` — Tonkeeper, `MyTonWallet`, Trust Wallet.
    #[default]
    Standard,
    /// `m/44'/607'/{index}'/0'/0'` — Ledger Live.
    LedgerLive,
}

/// Every variant of [`DerivationStyle`], returned by
/// [`kobe_primitives::DerivationStyle::all`].
const ALL_STYLES: &[DerivationStyle] = &[DerivationStyle::Standard, DerivationStyle::LedgerLive];

/// Tokens accepted by [`DerivationStyle::from_str`].
const ACCEPTED_TOKENS: &[&str] = &[
    "standard",
    "tonkeeper",
    "mytonwallet",
    "trust",
    "ledger-live",
    "ledgerlive",
    "live",
];

impl kobe_primitives::DerivationStyle for DerivationStyle {
    fn path(self, index: u32) -> String {
        match self {
            Self::Standard => format!("m/44'/607'/{index}'"),
            Self::LedgerLive => format!("m/44'/607'/{index}'/0'/0'"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Standard => "Standard (Tonkeeper)",
            Self::LedgerLive => "Ledger Live",
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
            "standard" | "tonkeeper" | "mytonwallet" | "trust" => Ok(Self::Standard),
            "ledger-live" | "ledgerlive" | "live" => Ok(Self::LedgerLive),
            _ => Err(ParseDerivationStyleError::new("ton", s, ACCEPTED_TOKENS)),
        }
    }
}
