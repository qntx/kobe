//! Error types for Filecoin wallet operations.

/// Errors that can occur during Filecoin wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Core kobe error (index overflow, BIP-32 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::DeriveError),

    /// `BLAKE2b` hashing error.
    #[error("hashing failed")]
    Hashing,
}
