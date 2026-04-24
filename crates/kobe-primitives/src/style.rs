//! Unified `DerivationStyle` trait and parse-error type.
//!
//! Several chains (`kobe-evm`, `kobe-svm`, `kobe-ton`) expose multiple
//! derivation-path layouts to stay compatible with the hardware and
//! software wallets users already own — `MetaMask` vs Ledger Live on EVM,
//! Phantom vs Trust Wallet on Solana, Tonkeeper vs Ledger Live on TON.
//!
//! Without a shared contract each chain grew its own `DerivationStyle`
//! enum with slightly different method names, its own
//! `ParseDerivationStyleError`, and its own `FromStr` error message.
//! This module collapses all three concerns into one
//! [`DerivationStyle`] trait + one shared
//! [`ParseDerivationStyleError`] so downstream callers and generic
//! helpers (CLI rendering, property tests, agent tooling) can speak to
//! any chain uniformly.
//!
//! # Contract
//!
//! Every chain's `DerivationStyle` enum is expected to:
//!
//! - Be `Copy + Eq + Hash + Default + Debug + Display` (trivial).
//! - Implement [`FromStr`] with an exhaustive alias set; the returned
//!   error must be this module's [`ParseDerivationStyleError`].
//! - Implement [`path`](DerivationStyle::path) returning the canonical
//!   BIP-32 / SLIP-10 path string for a given account index.
//! - Implement [`name`](DerivationStyle::name) returning a stable,
//!   human-readable label used by CLI output.
//! - Implement [`all`](DerivationStyle::all) returning every variant as
//!   a `'static` slice, so CLI / test code can enumerate styles without
//!   hand-maintaining a parallel list.

use alloc::string::String;
use core::fmt;
use core::hash::Hash;
use core::str::FromStr;

/// Trait implemented by every chain's `DerivationStyle` enum.
///
/// See the [module documentation](self) for the full contract.
pub trait DerivationStyle:
    Copy
    + Eq
    + Hash
    + Default
    + fmt::Debug
    + fmt::Display
    + FromStr<Err = ParseDerivationStyleError>
    + 'static
{
    /// Build the BIP-32 / SLIP-10 derivation path for account `index`.
    ///
    /// The returned `String` is owned because most call sites immediately
    /// feed it into a `bip32` / `slip10` parser that needs `&str`; the
    /// one-alloc-per-derivation cost is negligible against the
    /// secp256k1 / ed25519 key math that follows.
    fn path(self, index: u32) -> String;

    /// Human-readable name for CLI output and help text.
    ///
    /// Kept stable across library versions so CLI users see identical
    /// strings after upgrades.
    fn name(self) -> &'static str;

    /// Every variant of this enum in a `'static` slice.
    ///
    /// Powers CLI listing (`kobe evm styles`) and property tests that
    /// want to iterate over the whole style set without hand-maintaining
    /// a parallel list.
    fn all() -> &'static [Self];
}

/// Error returned when [`FromStr`] fails on a chain's `DerivationStyle`.
///
/// Carries the chain name, the rejected input, and the full accepted
/// token list (aliases included). The `Display` impl produces a single
/// actionable diagnostic so CLI error output needs no further massaging.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseDerivationStyleError {
    chain: &'static str,
    input: String,
    accepted: &'static [&'static str],
}

impl ParseDerivationStyleError {
    /// Construct a new error.
    ///
    /// `chain` is typically a short lowercase identifier (`"ethereum"`,
    /// `"solana"`, `"ton"`); `accepted` must list every alias the chain's
    /// [`FromStr`] implementation recognises, in the order they should
    /// appear in the human-readable message.
    #[inline]
    #[must_use]
    pub fn new(
        chain: &'static str,
        input: impl Into<String>,
        accepted: &'static [&'static str],
    ) -> Self {
        Self {
            chain,
            input: input.into(),
            accepted,
        }
    }

    /// Chain that rejected the input (`"ethereum"`, `"solana"`, …).
    #[inline]
    #[must_use]
    pub const fn chain(&self) -> &'static str {
        self.chain
    }

    /// The user-supplied string that failed to parse.
    #[inline]
    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Full accepted alias list, in display order.
    #[inline]
    #[must_use]
    pub const fn accepted(&self) -> &'static [&'static str] {
        self.accepted
    }
}

impl fmt::Display for ParseDerivationStyleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} derivation style '{}', expected one of: {}",
            self.chain,
            self.input,
            Joined(self.accepted),
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseDerivationStyleError {}

/// Inline `&str` joiner used by the `Display` impl to avoid allocating
/// an intermediate `String` in `no_std + alloc` builds where
/// `[&str]::join` is behind `std`.
struct Joined<'a>(&'a [&'a str]);

impl fmt::Display for Joined<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for s in self.0 {
            if first {
                first = false;
            } else {
                f.write_str(", ")?;
            }
            f.write_str(s)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn error_display_lists_every_accepted_token() {
        let err = ParseDerivationStyleError::new("ethereum", "bogus", &["standard", "live"]);
        assert_eq!(
            err.to_string(),
            "invalid ethereum derivation style 'bogus', expected one of: standard, live"
        );
    }

    #[test]
    fn error_accessors_roundtrip() {
        let err = ParseDerivationStyleError::new("solana", "bogus", &["a", "b"]);
        assert_eq!(err.chain(), "solana");
        assert_eq!(err.input(), "bogus");
        assert_eq!(err.accepted(), &["a", "b"]);
    }

    #[test]
    fn joined_empty_is_empty() {
        assert_eq!(Joined(&[]).to_string(), "");
    }

    #[test]
    fn joined_single_has_no_separator() {
        assert_eq!(Joined(&["a"]).to_string(), "a");
    }
}
