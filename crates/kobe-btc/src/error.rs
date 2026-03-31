//! Error types for Bitcoin wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors from Bitcoin HD derivation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Core kobe error (index overflow, etc.).
    #[error(transparent)]
    Core(#[from] kobe_core::Error),

    /// BIP-32 derivation error.
    #[error("bip32: {0}")]
    Bip32(#[cfg_attr(feature = "std", from)] bitcoin::bip32::Error),

    /// Invalid derivation path.
    #[cfg(feature = "alloc")]
    #[error("{0}")]
    InvalidDerivationPath(String),

    /// Invalid private key.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Secp256k1 error.
    #[error("secp256k1: {0}")]
    Secp256k1(#[cfg_attr(feature = "std", from)] bitcoin::secp256k1::Error),
}

#[cfg(not(feature = "std"))]
impl From<bitcoin::bip32::Error> for Error {
    fn from(e: bitcoin::bip32::Error) -> Self {
        Self::Bip32(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<bitcoin::secp256k1::Error> for Error {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}
