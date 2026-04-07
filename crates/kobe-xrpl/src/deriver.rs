//! XRP Ledger address derivation from a unified wallet.
//!
//! Derives classic `r`-addresses using BIP-44 coin type 144 (secp256k1).
//!
//! ## Address algorithm
//!
//! 1. Derive a secp256k1 key pair at `m/44'/144'/0'/0/{index}`
//! 2. Take the 33-byte compressed public key
//! 3. Hash160: `RIPEMD-160(SHA-256(pubkey))` → 20 bytes (Account ID)
//! 4. Prepend version byte `0x00`
//! 5. Compute checksum: first 4 bytes of `SHA-256(SHA-256(versioned_payload))`
//! 6. Encode `versioned_payload || checksum` with XRPL base58 alphabet

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};

pub use kobe_primitives::DerivedAccount;
use kobe_primitives::{Derive, Wallet};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::DeriveError;

/// XRPL base58 alphabet (differs from Bitcoin's).
///
/// `rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz`
const XRPL_ALPHABET: bs58::Alphabet = *bs58::Alphabet::RIPPLE;

/// XRPL account address version byte.
const ACCOUNT_VERSION: u8 = 0x00;

/// XRP Ledger address deriver.
///
/// Uses BIP-44 coin type 144 with secp256k1.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Wallet seed reference.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create an XRPL deriver.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive at an arbitrary path (internal).
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = kobe_primitives::bip32::DerivedSecp256k1Key::derive(self.wallet.seed(), path)?;
        let pubkey_bytes = key.compressed_pubkey();
        let address = encode_classic_address(&pubkey_bytes);

        Ok(DerivedAccount::new(
            path.into(),
            key.private_key_hex(),
            key.compressed_pubkey_hex(),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        let path = format!("m/44'/144'/0'/0/{index}");
        self.derive_at_path(&path)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at_path(path)
    }
}

/// Hash160: SHA-256 then RIPEMD-160.
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

/// Double SHA-256 (used for checksum).
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Encode a compressed public key as an XRPL classic `r`-address.
///
/// Algorithm: `base58_xrpl(0x00 || Hash160(pubkey) || checksum)`
fn encode_classic_address(compressed_pubkey: &[u8]) -> String {
    let account_id = hash160(compressed_pubkey);

    // version_byte(1) + account_id(20) = 21 bytes
    let mut payload = Vec::with_capacity(25);
    payload.push(ACCOUNT_VERSION);
    payload.extend_from_slice(&account_id);

    // checksum = first 4 bytes of double-SHA-256
    let checksum = double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);

    bs58::encode(&payload)
        .with_alphabet(&XRPL_ALPHABET)
        .into_string()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test assertions")]
mod tests {
    use kobe_primitives::DeriveExt;

    use super::*;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> Wallet {
        Wallet::from_mnemonic(MNEMONIC, None).unwrap()
    }

    #[test]
    fn address_starts_with_r() {
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        assert!(
            a.address.starts_with('r'),
            "XRPL address must start with 'r', got: {}",
            a.address
        );
    }

    #[test]
    fn address_length_valid() {
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        // XRPL classic addresses are 25-34 characters
        assert!(
            (25..=34).contains(&a.address.len()),
            "XRPL address length must be 25-34, got: {} ({})",
            a.address.len(),
            a.address
        );
    }

    #[test]
    fn deterministic() {
        let w = wallet();
        let a1 = Deriver::new(&w).derive(0).unwrap();
        let a2 = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a1.address, a2.address);
        assert_eq!(*a1.private_key, *a2.private_key);
    }

    #[test]
    fn different_indices() {
        let w = wallet();
        let d = Deriver::new(&w);
        assert_ne!(d.derive(0).unwrap().address, d.derive(1).unwrap().address);
    }

    #[test]
    fn derive_many_works() {
        let w = wallet();
        let accounts = Deriver::new(&w).derive_many(0, 3).unwrap();
        assert_eq!(accounts.len(), 3);
        assert_ne!(accounts[0].address, accounts[1].address);
        assert_ne!(accounts[1].address, accounts[2].address);
    }

    #[test]
    fn derive_path_custom() {
        let w = wallet();
        let a = Deriver::new(&w).derive_path("m/44'/144'/0'/0/5").unwrap();
        assert!(a.address.starts_with('r'));
    }

    #[test]
    fn passphrase_changes_address() {
        let w1 = Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let w2 = Wallet::from_mnemonic(MNEMONIC, Some("pass")).unwrap();
        assert_ne!(
            Deriver::new(&w1).derive(0).unwrap().address,
            Deriver::new(&w2).derive(0).unwrap().address,
        );
    }

    #[test]
    fn private_key_is_64_hex_chars() {
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        assert_eq!(a.private_key.len(), 64);
        assert!(hex::decode(&*a.private_key).is_ok());
    }

    #[test]
    fn public_key_is_compressed_33_bytes() {
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        let pk_bytes = hex::decode(&a.public_key).unwrap();
        assert_eq!(pk_bytes.len(), 33);
        assert!(pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03);
    }

    #[test]
    fn address_is_valid_base58_xrpl() {
        let w = wallet();
        let a = Deriver::new(&w).derive(0).unwrap();
        // Decode with XRPL alphabet to verify roundtrip
        let decoded = bs58::decode(&a.address)
            .with_alphabet(&XRPL_ALPHABET)
            .into_vec()
            .unwrap();
        // 1 (version) + 20 (account_id) + 4 (checksum) = 25 bytes
        assert_eq!(decoded.len(), 25);
        assert_eq!(decoded[0], ACCOUNT_VERSION);
    }
}
