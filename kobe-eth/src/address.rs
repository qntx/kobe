//! Ethereum address with EIP-55 checksum encoding.
//!
//! Uses `alloy_primitives::Address` as the underlying implementation.
//! Implements `kobe::Address` trait for unified wallet interface.

use alloy_primitives::Address as AlloyAddress;

use kobe::{Error, Result};

use crate::pubkey::PublicKey;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Ethereum address (20 bytes).
///
/// Wraps `alloy_primitives::Address` for EIP-55 checksum support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Address(AlloyAddress);

impl Address {
    /// Create from raw 20-byte address.
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(AlloyAddress::new(bytes))
    }

    /// Create from a public key.
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let raw = public_key.to_raw_bytes();
        // alloy_primitives computes keccak256 and takes last 20 bytes
        Self(AlloyAddress::from_raw_public_key(&raw))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 20] {
        self.0.as_ref()
    }

    /// Convert to EIP-55 checksummed string.
    #[cfg(feature = "alloc")]
    pub fn to_checksum_string(&self) -> String {
        self.0.to_checksum(None)
    }

    /// Get the inner alloy Address.
    pub const fn inner(&self) -> &AlloyAddress {
        &self.0
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "alloc")]
        {
            write!(f, "{}", self.to_checksum_string())
        }
        #[cfg(not(feature = "alloc"))]
        {
            write!(f, "0x")?;
            for byte in self.0.as_ref() {
                write!(f, "{:02x}", byte)?;
            }
            Ok(())
        }
    }
}

impl core::str::FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        kobe::Address::from_str(s)
    }
}

impl kobe::Address for Address {
    #[cfg(feature = "alloc")]
    fn from_str(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() != 40 {
            return Err(Error::InvalidLength {
                expected: 40,
                actual: s.len(),
            });
        }

        let mut bytes = [0u8; 20];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            bytes[i] = u8::from_str_radix(
                core::str::from_utf8(chunk).map_err(|_| Error::InvalidEncoding)?,
                16,
            )
            .map_err(|_| Error::InvalidEncoding)?;
        }

        Ok(Self(AlloyAddress::new(bytes)))
    }

    #[cfg(feature = "alloc")]
    fn to_string(&self) -> String {
        self.to_checksum_string()
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Self(AlloyAddress::new(bytes))
    }
}

impl From<AlloyAddress> for Address {
    fn from(addr: AlloyAddress) -> Self {
        Self(addr)
    }
}

impl From<Address> for [u8; 20] {
    fn from(addr: Address) -> Self {
        *addr.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EIP-55 test address
    const TEST_ADDR_LOWER: &str = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
    const TEST_ADDR_CHECKSUM: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

    mod parsing_tests {
        use super::*;

        #[test]
        fn from_checksum_str() {
            let addr: Address = TEST_ADDR_CHECKSUM.parse().unwrap();
            let expected = hex_literal::hex!("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
            assert_eq!(addr.as_bytes(), &expected);
        }

        #[test]
        fn from_lowercase_str() {
            let addr: Address = TEST_ADDR_LOWER.parse().unwrap();
            let expected = hex_literal::hex!("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
            assert_eq!(addr.as_bytes(), &expected);
        }
    }

    mod display_tests {
        use super::*;

        #[test]
        fn to_checksum_string() {
            let addr: Address = TEST_ADDR_LOWER.parse().unwrap();
            assert_eq!(addr.to_checksum_string(), TEST_ADDR_CHECKSUM);
        }

        #[test]
        fn display_uses_checksum() {
            let addr: Address = TEST_ADDR_LOWER.parse().unwrap();
            assert_eq!(addr.to_string(), TEST_ADDR_CHECKSUM);
        }
    }
}
