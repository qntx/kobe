//! Error types for Spark wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors from Spark HD derivation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Core kobe error (index overflow, BIP-32 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::DeriveError),

    /// Bech32m encoding of the Spark address failed.
    #[cfg(feature = "alloc")]
    #[error("bech32m encoding: {0}")]
    Bech32(String),
}
