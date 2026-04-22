//! Error types for Nostr wallet operations.
//!
//! Nostr derivation can fail during BIP-32 key derivation (covered by
//! [`kobe_primitives::DeriveError`]) or during NIP-19 bech32 encoding.

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Errors that can occur during Nostr wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Core kobe error (index overflow, BIP-32 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::DeriveError),

    /// NIP-19 bech32 encoding error.
    #[cfg(feature = "alloc")]
    #[error("nip-19 bech32 encoding error: {0}")]
    Bech32(String),
}
