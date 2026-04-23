//! Unified derivation trait and account types.
//!
//! This module defines the three cornerstone abstractions shared by every
//! chain crate in the workspace:
//!
//! - [`DerivedPublicKey`] — a strongly typed sum of every public-key shape
//!   produced by the HD pipeline. Replaces an opaque `Vec<u8>` with a
//!   length-safe, algorithm-tagged enum so cross-chain code can pattern
//!   match instead of inspecting byte lengths.
//! - [`DerivedAccount`] — the uniform view of a derived account (path,
//!   private key, public key, address) held by every chain.
//! - [`Derive`] / [`DeriveExt`] — the derivation traits. [`Derive`] uses an
//!   associated [`Account`](Derive::Account) type so chain-specific
//!   newtypes (`BtcAccount`, `SvmAccount`, `NostrAccount`, …) are returned
//!   *without* erasure, while the [`AsRef<DerivedAccount>`] bound keeps a
//!   unified read view available for generic code.

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::DeriveError;

/// Strongly typed public key emitted by an HD derivation.
///
/// Each variant fixes its length and cryptographic algorithm at the type
/// level, so consumers can branch on [`kind`](Self::kind) (or pattern
/// match) instead of inspecting a raw byte slice.
///
/// # Chain mapping
///
/// | Chain(s) | Variant | Length |
/// | --- | --- | --- |
/// | `kobe-btc`, `kobe-cosmos`, `kobe-spark`, `kobe-xrpl` | [`Secp256k1Compressed`](Self::Secp256k1Compressed) | 33 B |
/// | `kobe-evm`, `kobe-fil`, `kobe-tron` | [`Secp256k1Uncompressed`](Self::Secp256k1Uncompressed) | 65 B |
/// | `kobe-svm`, `kobe-sui`, `kobe-aptos`, `kobe-ton` | [`Ed25519`](Self::Ed25519) | 32 B |
/// | `kobe-nostr` | [`Secp256k1XOnly`](Self::Secp256k1XOnly) | 32 B |
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DerivedPublicKey {
    /// secp256k1 compressed SEC1 encoding (`0x02`/`0x03` prefix + 32-byte x).
    Secp256k1Compressed([u8; 33]),
    /// secp256k1 uncompressed SEC1 encoding (`0x04` prefix + 32-byte x + 32-byte y).
    Secp256k1Uncompressed([u8; 65]),
    /// Ed25519 32-byte public key (RFC 8032 §5.1.5).
    Ed25519([u8; 32]),
    /// BIP-340 x-only secp256k1 public key (32-byte x, parity dropped).
    Secp256k1XOnly([u8; 32]),
}

impl DerivedPublicKey {
    /// Borrow the raw bytes regardless of variant.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Secp256k1Compressed(b) => b,
            Self::Secp256k1Uncompressed(b) => b,
            Self::Ed25519(b) | Self::Secp256k1XOnly(b) => b,
        }
    }

    /// Length of the key in bytes.
    ///
    /// The method is named `byte_len` rather than `len` because a key is
    /// not a collection: the "length" is a constant per variant and has no
    /// emptiness invariant to pair with.
    #[inline]
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        match self {
            Self::Secp256k1Compressed(_) => 33,
            Self::Secp256k1Uncompressed(_) => 65,
            Self::Ed25519(_) | Self::Secp256k1XOnly(_) => 32,
        }
    }

    /// Lowercase hex encoding of the raw key bytes.
    #[inline]
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Cryptographic algorithm / encoding tag.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> PublicKeyKind {
        match self {
            Self::Secp256k1Compressed(_) => PublicKeyKind::Secp256k1Compressed,
            Self::Secp256k1Uncompressed(_) => PublicKeyKind::Secp256k1Uncompressed,
            Self::Ed25519(_) => PublicKeyKind::Ed25519,
            Self::Secp256k1XOnly(_) => PublicKeyKind::Secp256k1XOnly,
        }
    }

    /// Try to build [`Secp256k1Compressed`](Self::Secp256k1Compressed) from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Crypto`] if the slice is not exactly 33 bytes long.
    pub fn compressed(bytes: &[u8]) -> Result<Self, DeriveError> {
        <[u8; 33]>::try_from(bytes)
            .map(Self::Secp256k1Compressed)
            .map_err(|_| {
                DeriveError::Crypto(alloc::format!(
                    "compressed secp256k1 public key requires 33 bytes, got {}",
                    bytes.len()
                ))
            })
    }

    /// Try to build [`Secp256k1Uncompressed`](Self::Secp256k1Uncompressed) from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`DeriveError::Crypto`] if the slice is not exactly 65 bytes long.
    pub fn uncompressed(bytes: &[u8]) -> Result<Self, DeriveError> {
        <[u8; 65]>::try_from(bytes)
            .map(Self::Secp256k1Uncompressed)
            .map_err(|_| {
                DeriveError::Crypto(alloc::format!(
                    "uncompressed secp256k1 public key requires 65 bytes, got {}",
                    bytes.len()
                ))
            })
    }
}

impl AsRef<[u8]> for DerivedPublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Tag describing [`DerivedPublicKey`]'s variant without carrying the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PublicKeyKind {
    /// secp256k1 compressed SEC1.
    Secp256k1Compressed,
    /// secp256k1 uncompressed SEC1.
    Secp256k1Uncompressed,
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// BIP-340 x-only secp256k1.
    Secp256k1XOnly,
}

impl PublicKeyKind {
    /// Length in bytes of any key tagged with this kind.
    #[inline]
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Secp256k1Compressed => 33,
            Self::Secp256k1Uncompressed => 65,
            Self::Ed25519 | Self::Secp256k1XOnly => 32,
        }
    }

    /// Human-readable name (stable identifier for CLI / JSON output).
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Secp256k1Compressed => "secp256k1-compressed",
            Self::Secp256k1Uncompressed => "secp256k1-uncompressed",
            Self::Ed25519 => "ed25519",
            Self::Secp256k1XOnly => "secp256k1-xonly",
        }
    }
}

impl core::fmt::Display for PublicKeyKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A derived HD account — unified across all chains.
///
/// Holds the derivation path, a 32-byte private key (always zeroized on
/// drop), a typed [`DerivedPublicKey`], and the on-chain address string.
///
/// Fields are private; use the accessor methods to read them. Hex-encoded
/// views ([`private_key_hex`](Self::private_key_hex),
/// [`public_key_hex`](Self::public_key_hex)) are computed on demand.
///
/// Chain crates that need to expose chain-specific fields (e.g. BTC WIF,
/// Solana keypair, Nostr `nsec`) wrap `DerivedAccount` in a newtype and
/// implement [`AsRef<DerivedAccount>`] + `Deref<Target = DerivedAccount>`
/// on it. This guarantees generic code can always obtain the unified view
/// without erasing chain-specific information.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DerivedAccount {
    path: String,
    private_key: Zeroizing<[u8; 32]>,
    public_key: DerivedPublicKey,
    address: String,
}

impl DerivedAccount {
    /// Construct a derived account from its components.
    ///
    /// Chain crates call this after completing their derivation pipeline.
    #[inline]
    #[must_use]
    pub const fn new(
        path: String,
        private_key: Zeroizing<[u8; 32]>,
        public_key: DerivedPublicKey,
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

    /// Typed public key, carrying algorithm + length information at the type level.
    #[inline]
    #[must_use]
    pub const fn public_key(&self) -> &DerivedPublicKey {
        &self.public_key
    }

    /// Public key bytes, chain-specific layout.
    ///
    /// For pattern-matching on the algorithm, use
    /// [`public_key`](Self::public_key) instead.
    #[inline]
    #[must_use]
    pub const fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Lowercase hex-encoded public key.
    #[inline]
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.public_key.to_hex()
    }

    /// On-chain address in the chain's native format.
    #[inline]
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl AsRef<Self> for DerivedAccount {
    #[inline]
    fn as_ref(&self) -> &Self {
        self
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

/// Unified derivation trait implemented by every chain deriver.
///
/// Each chain implements this trait on its `Deriver` type and declares the
/// account newtype it returns via the associated [`Account`](Self::Account)
/// type. The [`AsRef<DerivedAccount>`] bound keeps the unified read view
/// available to generic callers, without erasing chain-specific metadata
/// (BTC WIF, Solana keypair, Nostr `nsec`, …).
///
/// Batch derivation is provided by the blanket [`DeriveExt`] trait.
///
/// # Example
///
/// ```no_run
/// use kobe_primitives::{Derive, DerivedAccount};
///
/// fn first_address<D: Derive>(d: &D) -> String {
///     // `as_ref` yields the unified view regardless of the chain newtype.
///     let account = d.derive(0).unwrap();
///     let view: &DerivedAccount = account.as_ref();
///     view.address().to_owned()
/// }
/// ```
pub trait Derive {
    /// The (possibly newtype) account returned by this deriver.
    ///
    /// Chains without chain-specific metadata set `Account = DerivedAccount`
    /// directly; chains with extra fields (BTC, SVM, Nostr) return their
    /// own `<Chain>Account` wrapper.
    type Account: AsRef<DerivedAccount>;

    /// The error type returned by derivation operations.
    type Error: core::fmt::Debug + core::fmt::Display + From<DeriveError>;

    /// Derive an account at the given index using the chain's default path.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or address encoding fails.
    fn derive(&self, index: u32) -> Result<Self::Account, Self::Error>;

    /// Derive an account at a custom path string.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid or derivation fails.
    fn derive_path(&self, path: &str) -> Result<Self::Account, Self::Error>;
}

/// Extension trait providing batch derivation for every [`Derive`] implementor.
///
/// Blanket-implemented for any `T: Derive`, so importing the trait is the
/// only requirement:
///
/// ```no_run
/// use kobe_primitives::{Derive, DeriveExt};
/// # struct D;
/// # impl Derive for D {
/// #     type Account = kobe_primitives::DerivedAccount;
/// #     type Error = kobe_primitives::DeriveError;
/// #     fn derive(&self, _: u32) -> Result<Self::Account, Self::Error> { unimplemented!() }
/// #     fn derive_path(&self, _: &str) -> Result<Self::Account, Self::Error> { unimplemented!() }
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
    fn derive_many(&self, start: u32, count: u32) -> Result<Vec<Self::Account>, Self::Error> {
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
        let mut pk = [0u8; 33];
        hex::decode_to_slice(
            "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
            &mut pk,
        )
        .unwrap();
        DerivedAccount::new(
            String::from("m/44'/60'/0'/0/0"),
            sk,
            DerivedPublicKey::Secp256k1Compressed(pk),
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
        assert_eq!(acct.public_key().kind(), PublicKeyKind::Secp256k1Compressed);
        assert_eq!(acct.public_key().byte_len(), 33);
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

    #[test]
    fn derived_public_key_compressed_constructor_validates_length() {
        let ok = DerivedPublicKey::compressed(&[0x02; 33]).unwrap();
        assert_eq!(ok.kind(), PublicKeyKind::Secp256k1Compressed);
        assert!(DerivedPublicKey::compressed(&[0u8; 32]).is_err());
        assert!(DerivedPublicKey::compressed(&[0u8; 34]).is_err());
    }

    #[test]
    fn derived_public_key_uncompressed_constructor_validates_length() {
        let ok = DerivedPublicKey::uncompressed(&[0x04; 65]).unwrap();
        assert_eq!(ok.kind(), PublicKeyKind::Secp256k1Uncompressed);
        assert!(DerivedPublicKey::uncompressed(&[0u8; 64]).is_err());
        assert!(DerivedPublicKey::uncompressed(&[0u8; 66]).is_err());
    }

    #[test]
    fn public_key_kind_length_round_trips() {
        let ed = DerivedPublicKey::Ed25519([0u8; 32]);
        assert_eq!(ed.byte_len(), PublicKeyKind::Ed25519.byte_len());
        let xonly = DerivedPublicKey::Secp256k1XOnly([0u8; 32]);
        assert_eq!(xonly.byte_len(), PublicKeyKind::Secp256k1XOnly.byte_len());
    }

    #[test]
    fn derived_account_as_ref_is_identity() {
        let acct = sample_account();
        let borrowed: &DerivedAccount = acct.as_ref();
        assert!(core::ptr::eq(borrowed, &raw const acct));
    }
}
