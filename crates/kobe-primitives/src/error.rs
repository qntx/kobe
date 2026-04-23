//! Unified error type for the entire workspace.
//!
//! Every chain crate (`kobe-evm`, `kobe-btc`, `kobe-svm`, …) surfaces its
//! failures through this single [`DeriveError`] enum, so callers can write
//! one `match` to handle errors from any chain. No chain defines its own
//! error type.

#[cfg(feature = "alloc")]
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
#[non_exhaustive]
pub enum DeriveError {
    /// BIP-39 mnemonic decoding / encoding failed.
    #[error("mnemonic: {0}")]
    Mnemonic(#[cfg_attr(feature = "std", from)] bip39::Error),

    /// Derivation path is malformed or unsupported.
    #[cfg(feature = "alloc")]
    #[error("derivation path: {0}")]
    Path(String),

    /// A cryptographic primitive (HMAC, BIP-32 / SLIP-10, PBKDF2, BLAKE2,
    /// secp256k1, …) failed.
    #[cfg(feature = "alloc")]
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// Caller-supplied input failed validation (word count, hex, index,
    /// unknown derivation style, …).
    #[cfg(feature = "alloc")]
    #[error("invalid input: {0}")]
    Input(String),

    /// Chain-specific address encoding failed (Bech32 / Bech32m, base58,
    /// base32, …).
    #[cfg(feature = "alloc")]
    #[error("address encoding: {0}")]
    AddressEncoding(String),
}

#[cfg(not(feature = "std"))]
impl From<bip39::Error> for DeriveError {
    fn from(e: bip39::Error) -> Self {
        Self::Mnemonic(e)
    }
}
