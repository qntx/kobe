//! Error types for TON wallet operations.

/// Errors from TON HD derivation.
///
/// All current failure modes surface through
/// [`kobe_primitives::DeriveError`]; the wrapper enum keeps the per-chain
/// error surface consistent so future TON-specific variants can be added
/// without a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Core kobe error (index overflow, SLIP-10 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::DeriveError),
}
