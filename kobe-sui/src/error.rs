//! Error types for Sui wallet operations.

/// Errors that can occur during Sui wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Core kobe error (index overflow, SLIP-10 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe::Error),
}
