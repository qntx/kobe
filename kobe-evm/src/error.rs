//! Error types for Ethereum wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors from Ethereum HD derivation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// HD key derivation or path parsing failed.
    #[cfg(feature = "alloc")]
    #[error("{0}")]
    Derivation(String),
}
