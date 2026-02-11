//! Error types for Ethereum wallet operations.
//!
//! This module defines all errors that can occur during Ethereum
//! wallet creation, key derivation, and address generation.

#[cfg(feature = "alloc")]
use alloc::string::String;

use core::fmt;

/// Errors that can occur during Ethereum wallet operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid private key format or value.
    InvalidPrivateKey,
    /// Invalid hex string format.
    InvalidHex,
    /// Key derivation error with details.
    #[cfg(feature = "alloc")]
    Derivation(String),
    /// Invalid derivation path.
    #[cfg(feature = "alloc")]
    InvalidPath(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
            Self::InvalidHex => write!(f, "invalid hex string"),
            #[cfg(feature = "alloc")]
            Self::Derivation(msg) => write!(f, "key derivation error: {msg}"),
            #[cfg(feature = "alloc")]
            Self::InvalidPath(path) => write!(f, "invalid derivation path: {path}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
