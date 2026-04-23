//! Error types for Bitcoin wallet operations.

/// Errors from Bitcoin HD derivation.
///
/// Path-parsing failures are surfaced through
/// [`kobe_primitives::DeriveError::Path`] (accessible via the [`Core`](Self::Core)
/// variant) to keep the error taxonomy consistent across chains.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Core kobe error (index overflow, path parsing, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::DeriveError),

    /// BIP-32 derivation error.
    #[error("bip32: {0}")]
    Bip32(#[cfg_attr(feature = "std", from)] bitcoin::bip32::Error),

    /// Invalid private key.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Secp256k1 error.
    #[error("secp256k1: {0}")]
    Secp256k1(#[cfg_attr(feature = "std", from)] bitcoin::secp256k1::Error),
}

#[cfg(not(feature = "std"))]
impl From<bitcoin::bip32::Error> for DeriveError {
    fn from(e: bitcoin::bip32::Error) -> Self {
        Self::Bip32(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<bitcoin::secp256k1::Error> for DeriveError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}
