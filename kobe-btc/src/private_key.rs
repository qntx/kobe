//! Bitcoin private key implementation.

use crate::address::{AddressFormat, BtcAddress};
use crate::network::Network;
use crate::public_key::BtcPublicKey;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::{CryptoRng, RngCore};
use kobe::hash::double_sha256;
use kobe::{Error, Result, Signature};
use zeroize::Zeroize;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Bitcoin private key based on secp256k1.
#[derive(Clone)]
pub struct BtcPrivateKey {
    inner: SigningKey,
    compressed: bool,
}

impl Zeroize for BtcPrivateKey {
    fn zeroize(&mut self) {
        // SigningKey internally zeroizes on drop
        let zeroed = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let _ = core::mem::replace(&mut self.inner, zeroed);
        self.compressed = false;
    }
}

impl Drop for BtcPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl BtcPrivateKey {
    /// Create a new random private key.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            inner: SigningKey::random(rng),
            compressed: true,
        }
    }

    /// Create from raw 32-byte secret.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let inner = SigningKey::from_slice(bytes).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(Self {
            inner,
            compressed: true,
        })
    }

    /// Set whether to use compressed public key.
    pub fn set_compressed(&mut self, compressed: bool) {
        self.compressed = compressed;
    }

    /// Check if using compressed public key.
    pub const fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// Serialize to raw 32-byte secret.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> BtcPublicKey {
        BtcPublicKey::from_signing_key(&self.inner, self.compressed)
    }

    /// Get the corresponding address.
    pub fn address(&self, network: Network, format: AddressFormat) -> Result<BtcAddress> {
        BtcAddress::from_public_key(&self.public_key(), network, format)
    }

    /// Import from WIF (Wallet Import Format).
    #[cfg(feature = "alloc")]
    pub fn from_wif(wif: &str) -> Result<(Self, Network)> {
        let decoded = bs58::decode(wif)
            .into_vec()
            .map_err(|_| Error::InvalidEncoding)?;

        // Minimum length: 1 (prefix) + 32 (key) + 4 (checksum) = 37
        // With compression flag: 38
        if decoded.len() < 37 || decoded.len() > 38 {
            return Err(Error::InvalidLength {
                expected: 37,
                actual: decoded.len(),
            });
        }

        // Verify checksum
        let payload_len = decoded.len() - 4;
        let checksum = &decoded[payload_len..];
        let computed = double_sha256(&decoded[..payload_len]);
        if checksum != &computed[..4] {
            return Err(Error::InvalidChecksum);
        }

        // Parse network from prefix
        let network = match decoded[0] {
            0x80 => Network::Mainnet,
            0xef => Network::Testnet,
            _ => return Err(Error::msg("unknown WIF network prefix")),
        };

        // Check compression flag
        let (key_bytes, compressed) = if decoded.len() == 38 {
            if decoded[33] != 0x01 {
                return Err(Error::msg("invalid compression flag"));
            }
            (&decoded[1..33], true)
        } else {
            (&decoded[1..33], false)
        };

        let inner = SigningKey::from_slice(key_bytes).map_err(|_| Error::InvalidPrivateKey)?;

        Ok((Self { inner, compressed }, network))
    }

    /// Export as WIF (Wallet Import Format).
    #[cfg(feature = "alloc")]
    pub fn to_wif(&self, network: Network) -> String {
        let mut data = [0u8; 34];
        data[0] = network.wif_prefix();
        data[1..33].copy_from_slice(&self.to_bytes());

        let payload_len = if self.compressed {
            data[33] = 0x01;
            34
        } else {
            33
        };

        let checksum = double_sha256(&data[..payload_len]);
        let mut result = [0u8; 38];
        result[..payload_len].copy_from_slice(&data[..payload_len]);
        result[payload_len..payload_len + 4].copy_from_slice(&checksum[..4]);

        bs58::encode(&result[..payload_len + 4]).into_string()
    }

    /// Sign a message hash (32 bytes, prehashed).
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature> {
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

    /// Sign a Bitcoin message with the standard prefix.
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        let hash = bitcoin_message_hash(message);
        self.sign_prehash(&hash)
    }
}

impl core::fmt::Debug for BtcPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BtcPrivateKey([REDACTED], compressed={})",
            self.compressed
        )
    }
}

#[cfg(feature = "alloc")]
impl core::str::FromStr for BtcPrivateKey {
    type Err = Error;

    /// Parse from WIF or hex string.
    /// Returns the private key (network info is discarded for hex input).
    fn from_str(s: &str) -> Result<Self> {
        // Try WIF first (starts with 5, K, L for mainnet; c, 9 for testnet)
        if s.len() >= 51
            && s.len() <= 52
            && let Ok((key, _)) = Self::from_wif(s)
        {
            return Ok(key);
        }

        // Try hex (64 characters = 32 bytes)
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() == 64 {
            let mut bytes = [0u8; 32];
            for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
                let hex_str = core::str::from_utf8(chunk).map_err(|_| Error::InvalidEncoding)?;
                bytes[i] = u8::from_str_radix(hex_str, 16).map_err(|_| Error::InvalidEncoding)?;
            }
            return Self::from_bytes(&bytes);
        }

        Err(Error::InvalidPrivateKey)
    }
}

/// Compute Bitcoin message hash with standard prefix.
fn bitcoin_message_hash(message: &[u8]) -> [u8; 32] {
    use kobe::hash::double_sha256;

    #[cfg(feature = "alloc")]
    {
        let prefix = b"\x18Bitcoin Signed Message:\n";
        let msg_len = encode_varint(message.len());

        let mut data = alloc::vec::Vec::with_capacity(prefix.len() + msg_len.len() + message.len());
        data.extend_from_slice(prefix);
        data.extend_from_slice(&msg_len);
        data.extend_from_slice(message);

        double_sha256(&data)
    }

    #[cfg(not(feature = "alloc"))]
    {
        // Simplified version for no_std without alloc
        double_sha256(message)
    }
}

#[cfg(feature = "alloc")]
fn encode_varint(n: usize) -> alloc::vec::Vec<u8> {
    if n < 0xfd {
        alloc::vec![n as u8]
    } else if n <= 0xffff {
        let mut v = alloc::vec![0xfd, 0, 0];
        v[1] = (n & 0xff) as u8;
        v[2] = ((n >> 8) & 0xff) as u8;
        v
    } else {
        let mut v = alloc::vec![0xfe, 0, 0, 0, 0];
        v[1] = (n & 0xff) as u8;
        v[2] = ((n >> 8) & 0xff) as u8;
        v[3] = ((n >> 16) & 0xff) as u8;
        v[4] = ((n >> 24) & 0xff) as u8;
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wif_export() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let wif = key.to_wif(Network::Mainnet);
        assert_eq!(wif, "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617");
    }

    #[test]
    fn test_wif_import_compressed() {
        let wif = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
        let (key, network) = BtcPrivateKey::from_wif(wif).unwrap();
        assert_eq!(network, Network::Mainnet);
        assert!(key.is_compressed());
        assert_eq!(
            key.to_bytes(),
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        );
    }

    #[test]
    fn test_wif_import_uncompressed() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let (key, network) = BtcPrivateKey::from_wif(wif).unwrap();
        assert_eq!(network, Network::Mainnet);
        assert!(!key.is_compressed());
    }

    #[test]
    fn test_wif_roundtrip() {
        let bytes =
            hex_literal::hex!("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let wif = key.to_wif(Network::Mainnet);
        let (recovered, network) = BtcPrivateKey::from_wif(&wif).unwrap();
        assert_eq!(network, Network::Mainnet);
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_from_str_wif() {
        let key: BtcPrivateKey = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
            .parse()
            .unwrap();
        assert!(key.is_compressed());
    }

    #[test]
    fn test_from_str_hex() {
        let key: BtcPrivateKey = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
            .parse()
            .unwrap();
        assert_eq!(
            key.to_bytes(),
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d")
        );
    }

    #[test]
    fn test_testnet_wif() {
        let bytes =
            hex_literal::hex!("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d");
        let key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let wif = key.to_wif(Network::Testnet);
        assert!(wif.starts_with('c'));
        let (recovered, network) = BtcPrivateKey::from_wif(&wif).unwrap();
        assert_eq!(network, Network::Testnet);
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }
}
