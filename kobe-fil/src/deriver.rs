//! Filecoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
pub use kobe::DerivedAccount;
use kobe::{Derive, Wallet};

use crate::Error;

/// Filecoin lowercase base32 alphabet (RFC 4648, no padding).
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Filecoin address deriver from a unified wallet seed.
///
/// Derives Filecoin f1 (secp256k1) addresses using BIP-44 path `m/44'/461'/0'/0/{index}`.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new Filecoin deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Internal: derive at an arbitrary BIP-32 path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        let key = kobe::bip32::DerivedSecp256k1Key::derive(self.wallet.seed(), path)?;
        let pubkey_bytes = key.uncompressed_pubkey();

        let payload = blake2b(&pubkey_bytes, 20);
        let protocol: u8 = 1;
        let checksum = {
            let mut data = Vec::with_capacity(1 + payload.len());
            data.push(protocol);
            data.extend_from_slice(&payload);
            blake2b(&data, 4)
        };
        let mut addr_bytes = Vec::with_capacity(payload.len() + checksum.len());
        addr_bytes.extend_from_slice(&payload);
        addr_bytes.extend_from_slice(&checksum);

        Ok(DerivedAccount::new(
            path.to_string(),
            key.private_key_hex(),
            key.uncompressed_pubkey_hex(),
            format!("f1{}", base32_encode(&addr_bytes)),
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = Error;

    fn derive(&self, index: u32) -> Result<DerivedAccount, Error> {
        self.derive_at_path(&format!("m/44'/461'/0'/0/{index}"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        self.derive_at_path(path)
    }
}

/// Compute a Blake2b hash with a variable output length.
fn blake2b(data: &[u8], output_len: usize) -> Vec<u8> {
    #[allow(clippy::expect_used)]
    let mut hasher = Blake2bVar::new(output_len).expect("valid output length");
    hasher.update(data);
    let mut buf = vec![0u8; output_len];
    #[allow(clippy::expect_used)]
    hasher
        .finalize_variable(&mut buf)
        .expect("valid output length");
    buf
}

/// Encode bytes using Filecoin's lowercase base32 (no padding).
fn base32_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1f) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    #[test]
    fn derive_starts_with_f1() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert!(
            derived.address.starts_with("f1"),
            "Filecoin address should start with f1, got: {}",
            derived.address
        );
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path, "m/44'/461'/0'/0/0");
    }

    #[test]
    fn deterministic() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_eq!(a1.address, a2.address);
    }

    #[test]
    fn different_indices_differ() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        assert_ne!(d.derive(0).unwrap().address, d.derive(1).unwrap().address);
    }

    #[test]
    fn base32_encode_known_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "my");
        assert_eq!(base32_encode(b"fo"), "mzxq");
        assert_eq!(base32_encode(b"foo"), "mzxw6");
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("pass")).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_ne!(a1.address, a2.address);
    }
}
