//! Casper signature algorithm / derivation-path style.

use alloc::format;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use kobe_primitives::ParseDerivationStyleError;

/// Signature algorithm and matching HD path layout for Casper.
///
/// Implements [`kobe_primitives::DerivationStyle`] so CLI / generic helpers
/// can enumerate algorithms the same way they enumerate EVM styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum KeyAlgo {
    /// secp256k1 — Ledger / casper-cli default path `m/44'/506'/0'/0/{index}`.
    ///
    /// This is Kobe's **default** for Casper interop with hardware wallets.
    #[default]
    Secp256k1,
    /// Ed25519 — SLIP-10 full-hardened path `m/44'/506'/0'/0'/{index}'`.
    ///
    /// Matches `casper-client keygen` default algorithm (different path
    /// convention from Ledger secp).
    Ed25519,
}

/// Every variant — returned by [`kobe_primitives::DerivationStyle::all`].
const ALL_ALGOS: &[KeyAlgo] = &[KeyAlgo::Secp256k1, KeyAlgo::Ed25519];

/// Tokens accepted by [`KeyAlgo::from_str`].
const ACCEPTED_TOKENS: &[&str] = &["secp256k1", "secp", "ecdsa", "ed25519", "ed", "eddsa"];

impl kobe_primitives::DerivationStyle for KeyAlgo {
    fn path(self, index: u32) -> String {
        match self {
            Self::Secp256k1 => format!("m/44'/506'/0'/0/{index}"),
            Self::Ed25519 => format!("m/44'/506'/0'/0'/{index}'"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Secp256k1 => "secp256k1",
            Self::Ed25519 => "ed25519",
        }
    }

    fn all() -> &'static [Self] {
        ALL_ALGOS
    }
}

impl fmt::Display for KeyAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<Self as kobe_primitives::DerivationStyle>::name(*self))
    }
}

impl FromStr for KeyAlgo {
    type Err = ParseDerivationStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "secp256k1" | "secp" | "ecdsa" => Ok(Self::Secp256k1),
            "ed25519" | "ed" | "eddsa" => Ok(Self::Ed25519),
            _ => Err(ParseDerivationStyleError::new("casper", s, ACCEPTED_TOKENS)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests")]
mod tests {
    use kobe_primitives::DerivationStyle as _;

    use super::*;

    #[test]
    fn paths() {
        assert_eq!(KeyAlgo::Secp256k1.path(0), "m/44'/506'/0'/0/0");
        assert_eq!(KeyAlgo::Secp256k1.path(7), "m/44'/506'/0'/0/7");
        assert_eq!(KeyAlgo::Ed25519.path(0), "m/44'/506'/0'/0'/0'");
        assert_eq!(KeyAlgo::Ed25519.path(3), "m/44'/506'/0'/0'/3'");
    }

    #[test]
    fn from_str_aliases() {
        assert_eq!("secp256k1".parse::<KeyAlgo>().unwrap(), KeyAlgo::Secp256k1);
        assert_eq!("SECP".parse::<KeyAlgo>().unwrap(), KeyAlgo::Secp256k1);
        assert_eq!("ed25519".parse::<KeyAlgo>().unwrap(), KeyAlgo::Ed25519);
        assert_eq!("ed".parse::<KeyAlgo>().unwrap(), KeyAlgo::Ed25519);
        assert!("rsa".parse::<KeyAlgo>().is_err());
    }

    #[test]
    fn default_is_secp() {
        assert_eq!(KeyAlgo::default(), KeyAlgo::Secp256k1);
    }
}
