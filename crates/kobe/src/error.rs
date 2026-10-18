//! Unified error type for the crate.

use alloc::string::String;

/// Error returned by every fallible kobe operation.
///
/// Variants partition failures by domain: mnemonic handling, entropy/word
/// counts, path syntax, index range, hardened-only schemes, unsupported
/// path shapes, and invalid derived key material.
#[derive(Debug, thiserror::Error)]
#[allow(
    clippy::error_impl_error,
    reason = "the single crate error type is deliberately named `Error`"
)]
#[non_exhaustive]
pub enum Error {
    /// BIP-39 mnemonic decoding failed.
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),
    /// Entropy must be 16, 20, 24, 28 or 32 bytes (12–24 words).
    #[error("invalid entropy length: expected 16, 20, 24, 28 or 32 bytes, got {0}")]
    EntropyLength(usize),
    /// Word count must be 12, 15, 18, 21 or 24.
    #[error("invalid word count {0:?} (expected 12, 15, 18, 21 or 24)")]
    WordCount(String),
    /// Derivation path syntax or template expansion failed.
    #[error("invalid derivation path: {0}")]
    Path(String),
    /// Child index exceeds the 31-bit BIP-32 range.
    #[error("child index {0} out of range (maximum 2147483647)")]
    IndexOutOfRange(u64),
    /// A hardened-only scheme (SLIP-10) received a non-hardened index.
    #[error("non-hardened index {0} on a hardened-only derivation scheme")]
    NotHardened(u32),
    /// The path does not match the shape this chain requires.
    #[error("path shape not supported by this chain: {0}")]
    UnsupportedPath(String),
    /// A value is not one of the accepted ids for the target enum.
    #[error("{0}")]
    InvalidValue(String),
    /// Derived key material was rejected by the curve or encoder.
    #[error("invalid derived key: {0}")]
    InvalidKey(String),
    /// The operating system RNG failed.
    #[cfg(feature = "os-rng")]
    #[error("system randomness failed: {0}")]
    Rng(String),
}
