//! Error types for Tron wallet operations.

/// Errors that can occur during Tron wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Core kobe error (index overflow, BIP-32 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::Error),
}
