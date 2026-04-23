//! Filecoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec, vec::Vec};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, DeriveExt, Wallet};

use crate::DeriveError;

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

    /// Derive `count` accounts starting at `start` using the default Filecoin path.
    ///
    /// Equivalent to [`DeriveExt::derive_many`] but available as an inherent method.
    ///
    /// # Errors
    ///
    /// Returns an error if any derivation fails or `start + count` overflows.
    pub fn derive_many(&self, start: u32, count: u32) -> Result<Vec<DerivedAccount>, DeriveError> {
        <Self as DeriveExt>::derive_many(self, start, count)
    }

    /// Internal: derive at an arbitrary BIP-32 path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = kobe_primitives::bip32::DerivedSecp256k1Key::derive(self.wallet.seed(), path)?;
        let pubkey_bytes = key.uncompressed_pubkey();

        let payload = blake2b(&pubkey_bytes, 20)?;
        let protocol: u8 = 1;
        let checksum_input = {
            let mut data = Vec::with_capacity(1 + payload.len());
            data.push(protocol);
            data.extend_from_slice(&payload);
            data
        };
        let checksum = blake2b(&checksum_input, 4)?;
        let mut addr_bytes = Vec::with_capacity(payload.len() + checksum.len());
        addr_bytes.extend_from_slice(&payload);
        addr_bytes.extend_from_slice(&checksum);

        Ok(DerivedAccount::new(
            String::from(path),
            key.private_key_bytes(),
            pubkey_bytes.to_vec(),
            format!("f1{}", base32_encode(&addr_bytes)?),
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(&format!("m/44'/461'/0'/0/{index}"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
}

/// Compute a Blake2b hash with a variable output length.
fn blake2b(data: &[u8], output_len: usize) -> Result<Vec<u8>, DeriveError> {
    let mut hasher = Blake2bVar::new(output_len).map_err(|_| DeriveError::Hashing)?;
    hasher.update(data);
    let mut buf = vec![0u8; output_len];
    hasher
        .finalize_variable(&mut buf)
        .map_err(|_| DeriveError::Hashing)?;
    Ok(buf)
}

/// Encode bytes using Filecoin's lowercase base32 (no padding).
fn base32_encode(data: &[u8]) -> Result<String, DeriveError> {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1f) as usize;
            result.push(*BASE32_ALPHABET.get(index).ok_or(DeriveError::Hashing)? as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
        result.push(*BASE32_ALPHABET.get(index).ok_or(DeriveError::Hashing)? as char);
    }

    Ok(result)
}

#[cfg(test)]
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
            derived.address().starts_with("f1"),
            "Filecoin address should start with f1, got: {}",
            derived.address()
        );
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path(), "m/44'/461'/0'/0/0");
    }

    #[test]
    fn deterministic() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_eq!(a1.address(), a2.address());
    }

    #[test]
    fn different_indices_differ() {
        let wallet = test_wallet();
        let d = Deriver::new(&wallet);
        assert_ne!(
            d.derive(0).unwrap().address(),
            d.derive(1).unwrap().address()
        );
    }

    #[test]
    fn base32_encode_known_vectors() {
        assert_eq!(base32_encode(b"").unwrap(), "");
        assert_eq!(base32_encode(b"f").unwrap(), "my");
        assert_eq!(base32_encode(b"fo").unwrap(), "mzxq");
        assert_eq!(base32_encode(b"foo").unwrap(), "mzxw6");
        assert_eq!(base32_encode(b"foobar").unwrap(), "mzxw6ytboi");
    }

    #[test]
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(TEST_MNEMONIC, Some("pass")).unwrap();
        let a1 = Deriver::new(&w1).derive(0).unwrap();
        let a2 = Deriver::new(&w2).derive(0).unwrap();
        assert_ne!(a1.address(), a2.address());
    }

    #[test]
    fn kat_filecoin_index0_privkey() {
        // Cross-verified with Python coincurve at BIP-44 m/44'/461'/0'/0/0
        let wallet = test_wallet();
        let a = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(
            a.private_key_hex().as_str(),
            "e1808079c6734eff9a187c917455dc1b2c70385e13f1cd6cecc94978e57f7f76"
        );
        assert!(a.address().starts_with("f1"));
    }
}
