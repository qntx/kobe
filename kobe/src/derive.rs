//! Unified derivation trait and account type.
//!
//! All chain-specific derivers implement [`Derive`], providing a consistent
//! API surface across chains. The output [`DerivedAccount`] is the same
//! regardless of which chain produced it.

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

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
/// # Example
///
/// ```ignore
/// use kobe::Derive;
///
/// fn derive_first_account(d: &impl Derive) -> kobe::DerivedAccount {
///     d.derive(0).unwrap()
/// }
/// ```
pub trait Derive {
    /// The error type returned by derivation operations.
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Derive an account at the given index using the chain's default path.
    fn derive(&self, index: u32) -> Result<DerivedAccount, Self::Error>;

    /// Derive `count` accounts starting at `start`.
    fn derive_many(&self, start: u32, count: u32) -> Result<Vec<DerivedAccount>, Self::Error> {
        let end = start
            .checked_add(count)
            .ok_or_else(|| self.overflow_error())?;
        (start..end).map(|i| self.derive(i)).collect()
    }

    /// Derive an account at a custom path string.
    fn derive_path(&self, path: &str) -> Result<DerivedAccount, Self::Error>;

    /// Produce an overflow error (used by default `derive_many` impl).
    ///
    /// Implementors must return an appropriate error for index overflow.
    #[doc(hidden)]
    fn overflow_error(&self) -> Self::Error;
}
