//! Error types for Ethereum wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors from Ethereum HD derivation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Core kobe error (index overflow, BIP-32 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_core::Error),

    /// Unknown derivation style string.
    #[cfg(feature = "alloc")]
    #[error("unknown derivation style: {0}")]
    UnknownDerivationStyle(String),
}
