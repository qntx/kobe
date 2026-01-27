//! Error types for Ethereum wallet operations.

use std::fmt;

/// Errors that can occur during Ethereum wallet operations.
#[derive(Debug)]
pub enum Error {
    /// Invalid mnemonic phrase.
    Mnemonic(bip39::Error),
    /// Invalid word count for mnemonic.
    InvalidWordCount(usize),
    /// Invalid private key.
    InvalidPrivateKey,
    /// Key derivation error.
    Derivation(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mnemonic(e) => write!(f, "mnemonic error: {e}"),
            Self::InvalidWordCount(n) => {
                write!(f, "invalid word count {n}, must be 12, 15, 18, 21, or 24")
            }
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
            Self::Derivation(msg) => write!(f, "key derivation error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mnemonic(e) => Some(e),
            Self::InvalidWordCount(_) | Self::InvalidPrivateKey | Self::Derivation(_) => None,
        }
    }
}

impl From<bip39::Error> for Error {
    fn from(err: bip39::Error) -> Self {
        Self::Mnemonic(err)
    }
}
