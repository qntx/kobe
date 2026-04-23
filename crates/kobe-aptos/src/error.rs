//! Error types for Aptos wallet operations.

/// Errors from Aptos HD derivation.
///
/// All current failure modes surface through
/// [`kobe_primitives::DeriveError`]; the wrapper enum keeps the per-chain
/// error surface consistent so future Aptos-specific variants can be added
/// without a breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeriveError {
    /// Core kobe error (index overflow, SLIP-10 derivation, etc.).
    #[error(transparent)]
    Core(#[from] kobe_primitives::DeriveError),
}
