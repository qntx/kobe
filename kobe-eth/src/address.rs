//! Ethereum address with EIP-55 checksum encoding.
//!
//! Implements `kobe::Address` trait for unified wallet interface.

use sha3::{Digest, Keccak256};

use kobe::{Error, Result};

use crate::public_key::EthPublicKey;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Ethereum address (20 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EthAddress([u8; 20]);

impl EthAddress {
    /// Create from raw 20-byte address.
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Create from a public key.
    pub fn from_public_key(public_key: &EthPublicKey) -> Self {
        let raw = public_key.to_raw_bytes();
        let hash = Keccak256::digest(raw);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        Self(addr)
    }

    /// Get the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Convert to EIP-55 checksummed string.
    #[cfg(feature = "alloc")]
    pub fn to_checksum_string(&self) -> String {
        let hex_addr = to_hex_lower(&self.0);
        let hash = Keccak256::digest(hex_addr.as_bytes());

        let mut result = String::with_capacity(42);
        result.push_str("0x");

        for (i, c) in hex_addr.chars().enumerate() {
            if c.is_ascii_alphabetic() {
                let hash_nibble = if i % 2 == 0 {
                    hash[i / 2] >> 4
                } else {
                    hash[i / 2] & 0x0f
                };

                if hash_nibble >= 8 {
                    result.push(c.to_ascii_uppercase());
                } else {
                    result.push(c.to_ascii_lowercase());
                }
            } else {
                result.push(c);
            }
        }

        result
    }
}

#[cfg(feature = "alloc")]
fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
}

impl core::fmt::Debug for EthAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EthAddress(0x")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl core::fmt::Display for EthAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "alloc")]
        {
            write!(f, "{}", self.to_checksum_string())
        }
        #[cfg(not(feature = "alloc"))]
        {
            write!(f, "0x")?;
            for byte in &self.0 {
                write!(f, "{:02x}", byte)?;
            }
            Ok(())
        }
    }
}

impl core::str::FromStr for EthAddress {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        kobe::Address::from_str(s)
    }
}

impl kobe::Address for EthAddress {
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

        Ok(Self(bytes))
    }

    #[cfg(feature = "alloc")]
    fn to_string(&self) -> String {
        self.to_checksum_string()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for EthAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for EthAddress {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl From<EthAddress> for [u8; 20] {
    fn from(addr: EthAddress) -> Self {
        addr.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        let addr: EthAddress = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
            .parse()
            .unwrap();
        let expected = hex_literal::hex!("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert_eq!(addr.as_bytes(), &expected);
    }

    #[test]
    fn test_checksum() {
        let addr: EthAddress = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
            .parse()
            .unwrap();
        assert_eq!(
            addr.to_checksum_string(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    #[test]
    fn test_display() {
        let addr: EthAddress = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
            .parse()
            .unwrap();
        let displayed = addr.to_string();
        assert_eq!(displayed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }
}
