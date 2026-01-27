//! Error types for Bitcoin wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

use core::fmt;

/// Errors that can occur during Bitcoin wallet operations.
#[derive(Debug)]
pub enum Error {
    /// Invalid mnemonic phrase.
    Mnemonic(bip39::Error),
    /// BIP32 derivation error.
    Bip32(bitcoin::bip32::Error),
    /// Invalid word count for mnemonic.
    InvalidWordCount(usize),
    /// Invalid derivation path.
    #[cfg(feature = "alloc")]
    InvalidDerivationPath(String),
    /// Invalid WIF (Wallet Import Format) private key.
    InvalidWif,
    /// Secp256k1 error.
    Secp256k1(bitcoin::secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mnemonic(e) => write!(f, "mnemonic error: {e}"),
            Self::Bip32(e) => write!(f, "BIP32 derivation error: {e}"),
            Self::InvalidWordCount(n) => {
                write!(f, "invalid word count {n}, must be 12, 15, 18, 21, or 24")
            }
            #[cfg(feature = "alloc")]
            Self::InvalidDerivationPath(p) => write!(f, "invalid derivation path: {p}"),
            Self::InvalidWif => write!(f, "invalid WIF format"),
            Self::Secp256k1(e) => write!(f, "secp256k1 error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mnemonic(e) => Some(e),
            Self::Bip32(e) => Some(e),
            Self::Secp256k1(e) => Some(e),
            Self::InvalidWordCount(_) | Self::InvalidWif => None,
            #[cfg(feature = "alloc")]
            Self::InvalidDerivationPath(_) => None,
        }
    }
}

impl From<bip39::Error> for Error {
    fn from(err: bip39::Error) -> Self {
        Self::Mnemonic(err)
    }
}

impl From<bitcoin::bip32::Error> for Error {
    fn from(err: bitcoin::bip32::Error) -> Self {
        Self::Bip32(err)
    }
}

impl From<bitcoin::secp256k1::Error> for Error {
    fn from(err: bitcoin::secp256k1::Error) -> Self {
        Self::Secp256k1(err)
    }
}
