//! Error types for Solana wallet operations.
//!
//! This module defines all errors that can occur during Solana
//! wallet creation, key derivation, and address generation.

#[cfg(feature = "alloc")]
use alloc::string::String;
use core::fmt;

/// Errors that can occur during Solana wallet operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Key derivation failed with details.
    #[cfg(feature = "alloc")]
    Derivation(String),
    /// Key derivation failed (no details in no_std).
    #[cfg(not(feature = "alloc"))]
    Derivation,
    /// Invalid seed length.
    InvalidSeedLength,
    /// Invalid hex string format.
    InvalidHex,
    /// Ed25519 signature error.
    Signature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "alloc")]
            Self::Derivation(msg) => write!(f, "derivation error: {msg}"),
            #[cfg(not(feature = "alloc"))]
            Self::Derivation => write!(f, "derivation error"),
            Self::InvalidSeedLength => write!(f, "invalid seed length"),
            Self::InvalidHex => write!(f, "invalid hex string"),
            Self::Signature => write!(f, "signature error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
