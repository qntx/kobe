//! Error types for XRPL wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors that can occur during XRPL wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Core kobe error (index overflow, BIP-32 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::DeriveError),

    /// Address encoding error.
    #[cfg(feature = "alloc")]
    #[error("address encoding error: {0}")]
    AddressEncoding(String),
}
