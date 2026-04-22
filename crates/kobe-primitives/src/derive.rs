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

    /// Decode the hex-encoded private key into raw 32-byte material.
    ///
    /// Every chain deriver in this workspace produces a 32-byte scalar
    /// (secp256k1 for EVM/BTC/Cosmos/Tron/Spark/Filecoin/XRPL/Nostr,
    /// Ed25519 for SVM/SUI/TON/Aptos), so the output is fixed-length.
    /// The returned buffer is zeroized on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored hex is malformed or not exactly
    /// 32 bytes. Derivers in this workspace never produce malformed data,
    /// so this error is unexpected in normal use.
    pub fn private_key_bytes(&self) -> Result<Zeroizing<[u8; 32]>, DeriveError> {
        let mut buf = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(self.private_key.as_str(), buf.as_mut_slice())
            .map_err(|e| DeriveError::InvalidHex(alloc::format!("private_key: {e}")))?;
        Ok(buf)
    }

    /// Decode the hex-encoded public key into raw bytes.
    ///
    /// Length is chain-specific: 33 for compressed secp256k1, 65 for
    /// uncompressed, 32 for Ed25519 / x-only secp256k1.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored hex is malformed.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, DeriveError> {
        hex::decode(&self.public_key)
            .map_err(|e| DeriveError::InvalidHex(alloc::format!("public_key: {e}")))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_account() -> DerivedAccount {
        DerivedAccount::new(
            String::from("m/44'/60'/0'/0/0"),
            Zeroizing::new(String::from(
                "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
            )),
            String::from("0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"),
            String::from("0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        )
    }

    #[test]
    fn private_key_bytes_roundtrip() {
        let acct = sample_account();
        let bytes = acct.private_key_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(hex::encode(*bytes), acct.private_key.as_str());
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let acct = sample_account();
        let bytes = acct.public_key_bytes().unwrap();
        assert_eq!(bytes.len(), 33);
        assert_eq!(hex::encode(&bytes), acct.public_key);
    }

    #[test]
    fn private_key_bytes_rejects_short_hex() {
        let bad = DerivedAccount::new(
            String::from("m/0"),
            Zeroizing::new(String::from("deadbeef")),
            String::new(),
            String::new(),
        );
        assert!(matches!(
            bad.private_key_bytes(),
            Err(DeriveError::InvalidHex(_))
        ));
    }

    #[test]
    fn public_key_bytes_rejects_non_hex() {
        let bad = DerivedAccount::new(
            String::from("m/0"),
            Zeroizing::new(String::new()),
            String::from("not-hex!"),
            String::new(),
        );
        assert!(matches!(
            bad.public_key_bytes(),
            Err(DeriveError::InvalidHex(_))
        ));
    }
}
