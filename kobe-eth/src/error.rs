//! Error types for Ethereum wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

use core::fmt;

/// Errors that can occur during Ethereum wallet operations.
#[derive(Debug)]
pub enum Error {
    /// Invalid private key.
    InvalidPrivateKey,
    /// Key derivation error.
    #[cfg(feature = "alloc")]
    Derivation(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
            #[cfg(feature = "alloc")]
            Self::Derivation(msg) => write!(f, "key derivation error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
