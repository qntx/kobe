//! Error types for core wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors produced by core wallet and key-derivation operations.
///
/// The four variants partition errors by domain:
///
/// - [`Mnemonic`](Self::Mnemonic): BIP-39 decode / encode failures.
/// - [`Path`](Self::Path): invalid or malformed derivation paths.
/// - [`Crypto`](Self::Crypto): underlying cryptographic primitive failures
///   (HMAC, SLIP-10 / BIP-32 key math, PBKDF2).
/// - [`Input`](Self::Input): caller-supplied inputs that fail validation
///   (word count, hex encoding, empty password, prefix expansion, index overflow).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// BIP-39 mnemonic decoding / encoding failed.
    #[error("mnemonic: {0}")]
    Mnemonic(#[cfg_attr(feature = "std", from)] bip39::Error),

    /// Derivation path is malformed or unsupported.
    #[cfg(feature = "alloc")]
    #[error("derivation path: {0}")]
    Path(String),

    /// A cryptographic primitive (HMAC, SLIP-10, BIP-32, PBKDF2) failed.
    #[cfg(feature = "alloc")]
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// Caller-supplied input failed validation (word count, hex, index, etc.).
    #[cfg(feature = "alloc")]
    #[error("invalid input: {0}")]
    Input(String),
}

#[cfg(not(feature = "std"))]
impl From<bip39::Error> for DeriveError {
    fn from(e: bip39::Error) -> Self {
        Self::Mnemonic(e)
    }
}
