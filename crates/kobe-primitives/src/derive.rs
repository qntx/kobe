//! Unified derivation trait and account type.
//!
//! All chain-specific derivers implement [`Derive`], providing a consistent
//! API surface across chains. [`DeriveExt`] is automatically implemented for
//! all `Derive` types, providing batch derivation via [`derive_many`](DeriveExt::derive_many).

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::DeriveError;

/// A derived HD account — unified across all chains.
///
/// Holds the derivation path, a 32-byte private key, a chain-specific public
/// key (33 B compressed / 65 B uncompressed secp256k1 or 32 B Ed25519 /
/// x-only), and the on-chain address string. The private key is zeroized on
/// drop.
///
/// Fields are private; use the accessor methods to read them. Hex-encoded
/// views ([`private_key_hex`](Self::private_key_hex),
/// [`public_key_hex`](Self::public_key_hex)) are computed on demand.
#[derive(Debug, Clone)]
pub struct DerivedAccount {
    path: String,
    private_key: Zeroizing<[u8; 32]>,
    public_key: Vec<u8>,
    address: String,
}

impl DerivedAccount {
    /// Construct a derived account from its raw components.
    ///
    /// This is the single entry point; chain crates call it after completing
    /// their derivation pipeline.
    #[inline]
    #[must_use]
    pub const fn new(
        path: String,
        private_key: Zeroizing<[u8; 32]>,
        public_key: Vec<u8>,
        address: String,
    ) -> Self {
        Self {
            path,
            private_key,
            public_key,
            address,
        }
    }

    /// BIP-32 / SLIP-10 derivation path (e.g. `m/44'/60'/0'/0/0`).
    #[inline]
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Raw 32-byte private key (zeroized on drop).
    #[inline]
    #[must_use]
    pub const fn private_key_bytes(&self) -> &Zeroizing<[u8; 32]> {
        &self.private_key
    }

    /// Lowercase hex-encoded private key (64 chars, zeroized on drop).
    #[inline]
    #[must_use]
    pub fn private_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(*self.private_key))
    }

    /// Chain-specific public key bytes.
    ///
    /// The layout depends on the deriving chain; callers that need a
    /// uniform representation should convert with the chain's documented
    /// procedure. Current mapping:
    ///
    /// | Chain(s) | Length | Encoding |
    /// | --- | --- | --- |
    /// | `kobe-btc`, `kobe-cosmos`, `kobe-spark`, `kobe-xrpl` | **33 B** | secp256k1 **compressed** (`0x02`/`0x03` prefix + x) |
    /// | `kobe-evm`, `kobe-fil`, `kobe-tron` | **65 B** | secp256k1 **uncompressed** (`0x04` prefix + x + y) |
    /// | `kobe-svm`, `kobe-sui`, `kobe-aptos`, `kobe-ton` | **32 B** | Ed25519 |
    /// | `kobe-nostr` | **32 B** | BIP-340 / NIP-19 **x-only** secp256k1 |
    ///
    /// Cross-chain code that needs a single canonical form should inspect
    /// the length and branch accordingly, or rely on chain-specific
    /// `<Chain>Account` newtypes that expose typed views.
    #[inline]
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Lowercase hex-encoded public key.
    #[inline]
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    /// On-chain address in the chain's native format.
    #[inline]
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Derive a range of accounts by repeatedly invoking a derivation closure.
///
/// Generic building block for every chain's batch-derivation entry point:
/// validates `start + count` against `u32` overflow and collects the
/// results into a `Vec<T>`.
///
/// # Errors
///
/// Returns [`DeriveError::Input`] (wrapped via `E: From<DeriveError>`) if
/// `start + count` overflows `u32`, or propagates any error produced by
/// `f`.
///
/// # Example
///
/// ```no_run
/// use kobe_primitives::{DerivedAccount, DeriveError, derive_range};
///
/// fn batch(count: u32) -> Result<Vec<DerivedAccount>, DeriveError> {
///     derive_range(0, count, |_i| todo!("derive one"))
/// }
/// ```
pub fn derive_range<T, E, F>(start: u32, count: u32, f: F) -> Result<Vec<T>, E>
where
    F: FnMut(u32) -> Result<T, E>,
    E: From<DeriveError>,
{
    let end = start.checked_add(count).ok_or_else(|| {
        E::from(DeriveError::Input(String::from(
            "derive_many: start + count overflows u32",
        )))
    })?;
    (start..end).map(f).collect()
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
/// Import it to call `derive_many` on any deriver:
///
/// ```no_run
/// use kobe_primitives::{Derive, DeriveExt};
/// # struct D;
/// # impl Derive for D {
/// #     type Error = kobe_primitives::DeriveError;
/// #     fn derive(&self, _: u32) -> Result<kobe_primitives::DerivedAccount, Self::Error> { unimplemented!() }
/// #     fn derive_path(&self, _: &str) -> Result<kobe_primitives::DerivedAccount, Self::Error> { unimplemented!() }
/// # }
/// # let d = D;
/// let accounts = d.derive_many(0, 5).unwrap();
/// ```
pub trait DeriveExt: Derive {
    /// Derive `count` accounts starting at index `start`.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Input`] if `start + count` overflows `u32`,
    /// or propagates any derivation error.
    #[inline]
    fn derive_many(&self, start: u32, count: u32) -> Result<Vec<DerivedAccount>, Self::Error> {
        derive_range(start, count, |i| self.derive(i))
    }
}

impl<T: Derive> DeriveExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_account() -> DerivedAccount {
        let mut sk = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
            sk.as_mut_slice(),
        )
        .unwrap();
        DerivedAccount::new(
            String::from("m/44'/60'/0'/0/0"),
            sk,
            hex::decode("0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299")
                .unwrap(),
            String::from("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        )
    }

    #[test]
    fn accessors_expose_all_fields() {
        let acct = sample_account();
        assert_eq!(acct.path(), "m/44'/60'/0'/0/0");
        assert_eq!(acct.private_key_bytes().len(), 32);
        assert_eq!(
            acct.private_key_hex().as_str(),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
        assert_eq!(acct.public_key_bytes().len(), 33);
        assert_eq!(
            acct.public_key_hex(),
            "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"
        );
        assert_eq!(acct.address(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn private_key_hex_is_reversible() {
        let acct = sample_account();
        let hex = acct.private_key_hex();
        let mut decoded = [0u8; 32];
        hex::decode_to_slice(hex.as_str(), &mut decoded).unwrap();
        assert_eq!(&decoded, acct.private_key_bytes().as_ref());
    }
}
