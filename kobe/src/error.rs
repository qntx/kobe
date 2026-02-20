//! Error types for core wallet operations.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
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
    /// Mnemonic prefix is too short for unambiguous expansion.
    #[cfg(feature = "alloc")]
    PrefixTooShort {
        /// The prefix that was too short.
        prefix: String,
        /// Minimum required prefix length.
        min_len: usize,
    },
    /// Mnemonic prefix does not match any word in the wordlist.
    #[cfg(feature = "alloc")]
    UnknownPrefix(String),
    /// Mnemonic prefix matches multiple words in the wordlist.
    #[cfg(feature = "alloc")]
    AmbiguousPrefix {
        /// The ambiguous prefix.
        prefix: String,
        /// Words that match the prefix.
        candidates: Vec<String>,
    },
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
            #[cfg(feature = "alloc")]
            Self::PrefixTooShort { prefix, min_len } => {
                write!(f, "prefix \"{prefix}\" is too short (minimum {min_len} characters)")
            }
            #[cfg(feature = "alloc")]
            Self::UnknownPrefix(prefix) => {
                write!(f, "prefix \"{prefix}\" does not match any BIP-39 word")
            }
            #[cfg(feature = "alloc")]
            Self::AmbiguousPrefix { prefix, candidates } => {
                write!(f, "prefix \"{prefix}\" is ambiguous, matches: {}", candidates.join(", "))
            }
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
            #[cfg(feature = "alloc")]
            Self::PrefixTooShort { .. } => None,
            #[cfg(feature = "alloc")]
            Self::UnknownPrefix(_) => None,
            #[cfg(feature = "alloc")]
            Self::AmbiguousPrefix { .. } => None,
        }
    }
}

impl From<bip39::Error> for Error {
    fn from(err: bip39::Error) -> Self {
        Self::Mnemonic(err)
    }
}
