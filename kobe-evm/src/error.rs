//! Error types for Ethereum wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors that can occur during Ethereum wallet operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid private key format or value.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Invalid hex string format.
    #[error("invalid hex string")]
    InvalidHex,

    /// Key derivation error with details.
    #[cfg(feature = "alloc")]
    #[error("key derivation error: {0}")]
    Derivation(String),

    /// Invalid derivation path.
    #[cfg(feature = "alloc")]
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),
}
