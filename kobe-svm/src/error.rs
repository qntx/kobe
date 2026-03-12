//! Error types for Solana wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors that can occur during Solana wallet operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Key derivation failed with details.
    #[cfg(feature = "alloc")]
    #[error("derivation error: {0}")]
    Derivation(String),

    /// Key derivation failed (no details in no_std).
    #[cfg(not(feature = "alloc"))]
    #[error("derivation error")]
    Derivation,

    /// Invalid seed length.
    #[error("invalid seed length")]
    InvalidSeedLength,

    /// Invalid hex string format.
    #[error("invalid hex string")]
    InvalidHex,

    /// Ed25519 signature error.
    #[error("ed25519 signature error")]
    Signature,
}
