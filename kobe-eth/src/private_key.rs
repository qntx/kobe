//! Ethereum private key implementation.
//!
//! Provides secure Ethereum private key management with:
//! - Random key generation
//! - EIP-191 personal message signing
//! - EIP-712 typed data signing
//! - Automatic memory zeroization
//! - Implements `kobe::PrivateKey` trait

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::address::EthAddress;
use crate::public_key::EthPublicKey;
use k256::ecdsa::SigningKey;
use kobe::rand_core::{CryptoRng, RngCore};
use kobe::{Error, Result, Signature};

use kobe::PrivateKey as _;
use kobe::PublicKey as _;
use sha3::{Digest, Keccak256};
use zeroize::Zeroize;

/// Ethereum private key based on secp256k1.
#[derive(Clone)]
pub struct EthPrivateKey {
    inner: SigningKey,
}

impl Zeroize for EthPrivateKey {
    fn zeroize(&mut self) {
        // SigningKey internally zeroizes on drop
        // We create a new key and swap to trigger the drop
        let zeroed = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let _ = core::mem::replace(&mut self.inner, zeroed);
    }
}

impl Drop for EthPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl kobe::PrivateKey for EthPrivateKey {
    type PublicKey = EthPublicKey;

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self> {
        Ok(Self {
            inner: SigningKey::random(rng),
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let inner = SigningKey::from_slice(bytes).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    fn public_key(&self) -> Self::PublicKey {
        EthPublicKey::from_signing_key(&self.inner)
    }

    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature> {
        let (sig, recid) = self
            .inner
            .sign_prehash_recoverable(hash)
            .map_err(|_| Error::CryptoError)?;

        let bytes = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);

        Ok(Signature::new(r, s, recid.to_byte()))
    }
}

impl EthPrivateKey {
    /// Get the corresponding address.
    pub fn address(&self) -> EthAddress {
        self.public_key().to_address()
    }

    /// Sign a message with EIP-191 prefix.
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        let hash = eip191_hash_message(message);
        self.sign_prehash(&hash)
    }

    /// Sign EIP-712 typed data.
    ///
    /// The `domain_separator` and `struct_hash` should be pre-computed.
    /// Final hash = keccak256("\x19\x01" || domain_separator || struct_hash)
    pub fn sign_typed_data(
        &self,
        domain_separator: &[u8; 32],
        struct_hash: &[u8; 32],
    ) -> Result<Signature> {
        let hash = eip712_hash(domain_separator, struct_hash);
        self.sign_prehash(&hash)
    }

    /// Get access to the underlying signing key.
    pub fn as_signing_key(&self) -> &SigningKey {
        &self.inner
    }

    /// Export as hex string (without 0x prefix).
    #[cfg(feature = "alloc")]
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        let mut result = String::with_capacity(64);
        for byte in bytes {
            result.push_str(&alloc::format!("{:02x}", byte));
        }
        result
    }
}

impl core::fmt::Debug for EthPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EthPrivateKey([REDACTED])")
    }
}

impl core::str::FromStr for EthPrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() != 64 {
            return Err(Error::InvalidLength {
                expected: 64,
                actual: s.len(),
            });
        }

        let mut bytes = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            bytes[i] = u8::from_str_radix(
                core::str::from_utf8(chunk).map_err(|_| Error::InvalidEncoding)?,
                16,
            )
            .map_err(|_| Error::InvalidEncoding)?;
        }

        Self::from_bytes(&bytes)
    }
}

/// Compute EIP-191 message hash.
fn eip191_hash_message(message: &[u8]) -> [u8; 32] {
    let prefix_start = b"\x19Ethereum Signed Message:\n";
    let (len_buf, len_used) = format_usize(message.len());

    let mut hasher = Keccak256::new();
    hasher.update(prefix_start);
    hasher.update(&len_buf[..len_used]);
    hasher.update(message);
    hasher.finalize().into()
}

/// Compute EIP-712 typed data hash.
fn eip712_hash(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19\x01");
    hasher.update(domain_separator);
    hasher.update(struct_hash);
    hasher.finalize().into()
}

/// Format usize as string (no_std compatible).
/// Returns (buffer, length_used).
fn format_usize(mut n: usize) -> ([u8; 20], usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();

    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }

    // Left-align the result
    let len = buf.len() - i;
    buf.copy_within(i.., 0);
    (buf, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes() {
        let bytes =
            hex_literal::hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
        let key = EthPrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn test_from_str() {
        let key: EthPrivateKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
            .parse()
            .unwrap();
        let expected =
            hex_literal::hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
        assert_eq!(key.to_bytes(), expected);
    }

    #[test]
    fn test_address_derivation() {
        let key: EthPrivateKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
            .parse()
            .unwrap();
        let addr = key.address();
        assert_eq!(
            addr.to_string().to_lowercase(),
            "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
        );
    }

    #[test]
    fn test_to_hex() {
        let key: EthPrivateKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
            .parse()
            .unwrap();
        assert_eq!(
            key.to_hex(),
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
        );
    }

    #[test]
    fn test_eip712_sign() {
        let key: EthPrivateKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
            .parse()
            .unwrap();

        // Example domain separator and struct hash
        let domain = [1u8; 32];
        let struct_hash = [2u8; 32];

        let sig = key.sign_typed_data(&domain, &struct_hash).unwrap();
        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
    }
}
