//! Error types for Bitcoin wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors from Bitcoin HD derivation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// BIP-32 derivation error.
    #[error("bip32: {0}")]
    Bip32(#[from] bitcoin::bip32::Error),

    /// Invalid derivation path.
    #[cfg(feature = "alloc")]
    #[error("{0}")]
    InvalidDerivationPath(String),

    /// Invalid private key.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Secp256k1 error.
    #[error("secp256k1: {0}")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
}
