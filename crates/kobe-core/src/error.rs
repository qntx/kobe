//! Unified error type for the entire workspace.
//!
//! Every chain crate (`kobe-evm`, `kobe-btc`, `kobe-svm`, …) surfaces its
//! failures through this single [`Error`] enum, so callers can write
//! one `match` to handle errors from any chain. No chain defines its own
//! error type.

use alloc::string::String;

/// Errors produced by HD derivation, mnemonic handling, and address encoding.
///
/// Variants partition failures by domain:
///
/// - [`Mnemonic`](Self::Mnemonic) — BIP-39 decode / encode failures.
/// - [`Path`](Self::Path) — invalid or malformed derivation paths.
/// - [`Crypto`](Self::Crypto) — underlying cryptographic primitive failures
///   (HMAC, BIP-32 / SLIP-10 key math, PBKDF2, BLAKE2, secp256k1, etc.).
/// - [`Input`](Self::Input) — caller-supplied inputs that fail validation
///   (word count, hex encoding, empty password, prefix expansion, index
///   overflow, unknown derivation style).
/// - [`AddressEncoding`](Self::AddressEncoding) — chain-specific address
///   encoding failures (Bech32 / Bech32m HRP, base58check, base32, …).
#[derive(Debug, thiserror::Error)]
#[allow(
    clippy::error_impl_error,
    reason = "the unified workspace error type is deliberately named `Error`"
)]
#[non_exhaustive]
pub enum Error {
    /// BIP-39 mnemonic decoding / encoding failed.
    #[error("mnemonic: {0}")]
    Mnemonic(#[cfg_attr(feature = "std", from)] bip39::Error),

    /// Derivation path is malformed or unsupported.
    #[error("derivation path: {0}")]
    Path(String),

    /// A cryptographic primitive (HMAC, BIP-32 / SLIP-10, PBKDF2, BLAKE2,
    /// secp256k1, …) failed.
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// Caller-supplied input failed validation (word count, hex, index,
    /// unknown derivation style, …).
    #[error("invalid input: {0}")]
    Input(String),

    /// Chain-specific address encoding failed (Bech32 / Bech32m, base58,
    /// base32, …).
    #[error("address encoding: {0}")]
    AddressEncoding(String),
}

/// Stable machine-readable code for an [`Error`], shared with the
/// TypeScript implementation (`KobeError.code`); [`as_str`](Self::as_str)
/// returns the shared string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// BIP-39 mnemonic decoding / encoding failed.
    Mnemonic,
    /// Derivation path is malformed or unsupported.
    Path,
    /// A cryptographic primitive failed.
    Crypto,
    /// Caller-supplied input failed validation.
    Input,
    /// Chain-specific address encoding failed.
    AddressEncoding,
}

impl ErrorCode {
    /// The `KobeErrorCode` string used by the TypeScript implementation.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mnemonic => "mnemonic",
            Self::Path => "path",
            Self::Crypto => "crypto",
            Self::Input => "input",
            Self::AddressEncoding => "address-encoding",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error {
    /// Machine-readable code identifying which variant this error is.
    ///
    /// 1:1 with the variants and with `KobeError.code` in TypeScript.
    #[inline]
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Mnemonic(_) => ErrorCode::Mnemonic,
            Self::Path(_) => ErrorCode::Path,
            Self::Crypto(_) => ErrorCode::Crypto,
            Self::Input(_) => ErrorCode::Input,
            Self::AddressEncoding(_) => ErrorCode::AddressEncoding,
        }
    }
}

#[cfg(not(feature = "std"))]
impl From<bip39::Error> for Error {
    fn from(e: bip39::Error) -> Self {
        Self::Mnemonic(e)
    }
}
