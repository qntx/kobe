//! Error types for Solana wallet operations.

/// Errors that can occur during Solana wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Core kobe error (index overflow, SLIP-10 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::Error),

    /// Ed25519 signature error.
    #[error("ed25519 signature error")]
    Signature,
}
