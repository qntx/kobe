//! Error types for Cosmos wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors that can occur during Cosmos wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Core kobe error (index overflow, BIP-32 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::Error),

    /// Address encoding error.
    #[cfg(feature = "alloc")]
    #[error("address encoding error: {0}")]
    AddressEncoding(String),
}
