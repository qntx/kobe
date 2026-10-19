//! The [`Chain`] trait: one implementation per coin.

use alloc::vec::Vec;

use crate::{Account, DerivationPath, Error, Style, Wallet};

/// A chain: a set of derivation styles plus account derivation.
///
/// Implementors are small, stateless structs holding chain options
/// (network, address kind, …). Adding a chain means adding a feature-gated
/// module under `chains/` with one `Chain` impl.
pub trait Chain {
    /// Supported derivation styles; the first one is the default.
    fn styles(&self) -> Vec<Style>;

    /// Derive the account at `path`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the path is malformed, does not match a shape
    /// the chain supports, or key derivation fails.
    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error>;
}
