//! Error types for core wallet operations.

use core::fmt;

/// Errors that can occur during wallet operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Invalid mnemonic phrase.
    Mnemonic(bip39::Error),
    /// Invalid word count for mnemonic.
    InvalidWordCount(usize),
    /// Empty password provided for camouflage operation.
    #[cfg(feature = "camouflage")]
    EmptyPassword,
    /// PBKDF2 key derivation failed.
    #[cfg(feature = "camouflage")]
    KeyDerivation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mnemonic(e) => write!(f, "mnemonic error: {e}"),
            Self::InvalidWordCount(n) => {
                write!(f, "invalid word count {n}, must be 12, 15, 18, 21, or 24")
            }
            #[cfg(feature = "camouflage")]
            Self::EmptyPassword => write!(f, "password must not be empty"),
            #[cfg(feature = "camouflage")]
            Self::KeyDerivation => write!(f, "PBKDF2 key derivation failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mnemonic(e) => Some(e),
            Self::InvalidWordCount(_) => None,
            #[cfg(feature = "camouflage")]
            Self::EmptyPassword => None,
            #[cfg(feature = "camouflage")]
            Self::KeyDerivation => None,
        }
    }
}

impl From<bip39::Error> for Error {
    fn from(err: bip39::Error) -> Self {
        Self::Mnemonic(err)
    }
}
