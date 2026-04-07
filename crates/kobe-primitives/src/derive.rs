//! Unified derivation trait and account type.
//!
//! All chain-specific derivers implement [`Derive`], providing a consistent
//! API surface across chains. [`DeriveExt`] is automatically implemented for
//! all `Derive` types, providing batch derivation via [`derive_many`](DeriveExt::derive_many).

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::DeriveError;

/// A derived account from any chain.
///
/// Contains the derivation path, key material, and on-chain address.
/// The private key is zeroized on drop.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DerivedAccount {
    /// BIP-32/SLIP-10 derivation path used (e.g. `m/44'/60'/0'/0/0`).
    pub path: String,
    /// Private key in hex (zeroized on drop).
    pub private_key: Zeroizing<String>,
    /// Public key in hex.
    pub public_key: String,
    /// On-chain address in the chain's native format.
    pub address: String,
}

impl DerivedAccount {
    /// Create a new derived account.
    #[must_use]
    pub const fn new(
        path: String,
        private_key: Zeroizing<String>,
        public_key: String,
        address: String,
    ) -> Self {
        Self {
            path,
            private_key,
            public_key,
            address,
        }
    }
}

/// Unified derivation trait implemented by all chain derivers.
///
/// Provides a consistent API for deriving accounts regardless of the
/// underlying chain. Each chain crate (`kobe-evm`, `kobe-btc`, etc.)
/// implements this trait on its `Deriver` type.
///
/// Batch derivation is provided by the blanket [`DeriveExt`] trait.
///
/// # Example
///
/// ```no_run
/// use kobe_primitives::{Derive, DeriveExt, DerivedAccount};
///
/// fn derive_first_account<D: Derive>(d: &D) -> DerivedAccount {
///     d.derive(0).unwrap()
/// }
/// ```
pub trait Derive {
    /// The error type returned by derivation operations.
    type Error: core::fmt::Debug + core::fmt::Display + From<DeriveError>;

    /// Derive an account at the given index using the chain's default path.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or address encoding fails.
    fn derive(&self, index: u32) -> Result<DerivedAccount, Self::Error>;

    /// Derive an account at a custom path string.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or derivation fails.
    fn derive_path(&self, path: &str) -> Result<DerivedAccount, Self::Error>;
}

/// Extension trait providing batch derivation for all [`Derive`] implementors.
///
/// This trait is automatically implemented for any type implementing `Derive`.
pub trait DeriveExt: Derive {
    /// Derive `count` accounts starting at index `start`.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::IndexOverflow`] if `start + count` overflows `u32`.
    fn derive_many(&self, start: u32, count: u32) -> Result<Vec<DerivedAccount>, Self::Error> {
        let end = start.checked_add(count).ok_or(DeriveError::IndexOverflow)?;
        (start..end).map(|i| self.derive(i)).collect()
    }
}

impl<T: Derive> DeriveExt for T {}
