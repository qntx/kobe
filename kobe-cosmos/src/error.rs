//! Error types for Cosmos wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors that can occur during Cosmos wallet operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid private key format or value.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Key derivation error with details.
    #[cfg(feature = "alloc")]
    #[error("key derivation error: {0}")]
    Derivation(String),

    /// Address encoding error.
    #[cfg(feature = "alloc")]
    #[error("address encoding error: {0}")]
    AddressEncoding(String),
}
