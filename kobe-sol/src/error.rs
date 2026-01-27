//! Error types for Solana wallet operations.

use core::fmt;

/// Errors that can occur during Solana wallet operations.
#[derive(Debug)]
pub enum Error {
    /// Key derivation failed.
    Derivation(#[cfg(feature = "alloc")] alloc::string::String),
    /// Invalid seed length.
    InvalidSeedLength,
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
            Self::Signature => write!(f, "signature error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
