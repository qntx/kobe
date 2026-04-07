//! Error types for Aptos wallet operations.

/// Errors that can occur during Aptos wallet operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Core kobe error (index overflow, SLIP-10 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::DeriveError),
}
