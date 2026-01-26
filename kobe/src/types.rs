//! Core types used throughout the library.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A 32-byte secret key with automatic zeroization.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Create from a byte array
    #[inline]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Get a reference to the inner bytes
    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Get a mutable reference to the inner bytes
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Consume and return the inner bytes
    #[inline]
    pub fn into_bytes(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for SecretBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> core::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes<{}>[REDACTED]", N)
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

/// Type alias for 32-byte secret (private key, seed, etc.)
pub type Secret32 = SecretBytes<32>;

/// Type alias for 64-byte secret (seed)
pub type Secret64 = SecretBytes<64>;

/// A fixed-size byte array with display formatting.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes<const N: usize>(pub [u8; N]);

impl<const N: usize> Bytes<N> {
    /// Create a new instance with all zeros
    pub const fn zero() -> Self {
        Self([0u8; N])
    }

    /// Create from a byte array
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Get a reference to the inner bytes
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Get the length
    pub const fn len(&self) -> usize {
        N
    }

    /// Check if empty
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> AsRef<[u8]> for Bytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8]> for Bytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> From<[u8; N]> for Bytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> From<Bytes<N>> for [u8; N] {
    fn from(bytes: Bytes<N>) -> Self {
        bytes.0
    }
}

impl<const N: usize> core::ops::Deref for Bytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for Bytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> core::fmt::Debug for Bytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<const N: usize> core::fmt::Display for Bytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Type alias for 20-byte address (Ethereum)
pub type Address20 = Bytes<20>;

/// Type alias for 32-byte hash
pub type Hash32 = Bytes<32>;

/// Type alias for 33-byte compressed public key
pub type CompressedPubKey = Bytes<33>;

/// Type alias for 65-byte uncompressed public key
pub type UncompressedPubKey = Bytes<65>;
