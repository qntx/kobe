//! Error types for core wallet operations.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

/// Errors that can occur during wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Invalid mnemonic phrase.
    #[error("invalid mnemonic: {0}")]
    Mnemonic(#[from] bip39::Error),

    /// Invalid word count for mnemonic.
    #[error("invalid word count {0}, must be 12, 15, 18, 21, or 24")]
    InvalidWordCount(usize),

    /// Empty password provided for camouflage operation.
    #[cfg(feature = "camouflage")]
    #[error("password must not be empty")]
    EmptyPassword,

    /// PBKDF2 key derivation failed.
    #[cfg(feature = "camouflage")]
    #[error("PBKDF2 key derivation failed")]
    KeyDerivation,

    /// Mnemonic prefix is too short for unambiguous expansion.
    #[cfg(feature = "alloc")]
    #[error("prefix \"{prefix}\" is too short (minimum {min_len} characters)")]
    PrefixTooShort {
        /// The prefix that was too short.
        prefix: String,
        /// Minimum required prefix length.
        min_len: usize,
    },

    /// Mnemonic prefix does not match any word in the wordlist.
    #[cfg(feature = "alloc")]
    #[error("prefix \"{0}\" does not match any BIP-39 word")]
    UnknownPrefix(String),

    /// Mnemonic prefix matches multiple words in the wordlist.
    #[cfg(feature = "alloc")]
    #[error("prefix \"{prefix}\" is ambiguous, matches: {}", candidates.join(", "))]
    AmbiguousPrefix {
        /// The ambiguous prefix.
        prefix: String,
        /// Words that match the prefix.
        candidates: Vec<String>,
    },

    /// Index overflow in batch derivation.
    #[error("index overflow")]
    IndexOverflow,

    /// SLIP-10 Ed25519 derivation: invalid seed.
    #[cfg(feature = "slip10")]
    #[error("SLIP-10: invalid seed length")]
    Slip10InvalidSeed,

    /// SLIP-10 Ed25519 derivation: invalid path.
    #[cfg(feature = "slip10")]
    #[error("SLIP-10: {0}")]
    Slip10InvalidPath(String),

    /// BIP-32 secp256k1 derivation error.
    #[cfg(feature = "bip32")]
    #[error("BIP-32: {0}")]
    Bip32Derivation(String),
}
