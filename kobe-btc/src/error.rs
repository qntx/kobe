//! Error types for Bitcoin wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors that can occur during Bitcoin wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid mnemonic phrase.
    #[error("invalid mnemonic: {0}")]
    Mnemonic(#[from] bip39::Error),

    /// BIP32 derivation error.
    #[error("BIP32 derivation error: {0}")]
    Bip32(#[from] bitcoin::bip32::Error),

    /// Invalid word count for mnemonic.
    #[error("invalid word count {0}, must be 12, 15, 18, 21, or 24")]
    InvalidWordCount(usize),

    /// Invalid derivation path.
    #[cfg(feature = "alloc")]
    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// Invalid WIF (Wallet Import Format) private key.
    #[error("invalid WIF format")]
    InvalidWif,

    /// Invalid hex string.
    #[error("invalid hex string")]
    InvalidHex,

    /// Invalid private key.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Secp256k1 error.
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
}
