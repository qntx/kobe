//! Error types for the Kobe wallet library.

#[cfg(feature = "alloc")]
use alloc::string::String;

use core::fmt;

/// A specialized Result type for Kobe operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur in the Kobe wallet library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid private key bytes or format
    InvalidPrivateKey,
    /// Invalid public key bytes or format
    InvalidPublicKey,
    /// Invalid signature format or verification failed
    InvalidSignature,
    /// Invalid address format or network mismatch
    InvalidAddress,
    /// Checksum verification failed
    InvalidChecksum,
    /// Invalid byte length for the given operation
    InvalidLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length in bytes
        actual: usize,
    },
    /// Invalid encoding (hex, base58, bech32, etc.)
    InvalidEncoding,
    /// Invalid BIP-32 derivation path format
    InvalidDerivationPath,
    /// Invalid BIP-39 mnemonic phrase
    InvalidMnemonic,
    /// Word not found in BIP-39 wordlist
    InvalidWord,
    /// Invalid entropy length for mnemonic generation
    InvalidEntropyLength,
    /// ECDSA or other cryptographic operation failed
    CryptoError,
    /// Hardened derivation required but not used
    HardenedDerivationRequired,
    /// Maximum derivation depth exceeded
    MaxDepthExceeded,
    /// Unsupported operation for this key type
    UnsupportedOperation,
    /// Message with description
    #[cfg(feature = "alloc")]
    Message(String),
    /// Static message without allocation
    StaticMessage(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::InvalidAddress => write!(f, "invalid address"),
            Self::InvalidChecksum => write!(f, "checksum verification failed"),
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid length: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidEncoding => write!(f, "invalid encoding"),
            Self::InvalidDerivationPath => write!(f, "invalid BIP-32 derivation path"),
            Self::InvalidMnemonic => write!(f, "invalid mnemonic phrase"),
            Self::InvalidWord => write!(f, "word not found in wordlist"),
            Self::InvalidEntropyLength => write!(f, "invalid entropy length"),
            Self::CryptoError => write!(f, "cryptographic operation failed"),
            Self::HardenedDerivationRequired => {
                write!(f, "hardened derivation required for this operation")
            }
            Self::MaxDepthExceeded => write!(f, "maximum derivation depth exceeded"),
            Self::UnsupportedOperation => write!(f, "unsupported operation"),
            #[cfg(feature = "alloc")]
            Self::Message(msg) => write!(f, "{}", msg),
            Self::StaticMessage(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error {
    /// Create a new error with a static message.
    #[inline]
    pub const fn msg(message: &'static str) -> Self {
        Self::StaticMessage(message)
    }

    /// Create a length mismatch error.
    #[inline]
    pub const fn length(expected: usize, actual: usize) -> Self {
        Self::InvalidLength { expected, actual }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<k256::ecdsa::Error> for Error {
    fn from(_: k256::ecdsa::Error) -> Self {
        Self::CryptoError
    }
}

impl From<k256::elliptic_curve::Error> for Error {
    fn from(_: k256::elliptic_curve::Error) -> Self {
        Self::CryptoError
    }
}
