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
        let key = self.wallet.derive_secp256k1(path)?;
        let pubkey_bytes = key.compressed_pubkey();
        let address = encode_classic_address(&pubkey_bytes);

        Ok(DerivedAccount::new(
            path.into(),
            key.private_key_bytes(),
            pubkey_bytes.to_vec(),
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
mod tests {
    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> Wallet {
        Wallet::from_mnemonic(MNEMONIC, None).unwrap()
    }

    /// Known-answer test for the canonical BIP-39 `abandon…about` mnemonic.
    ///
    /// Address and private key are independently re-computed from
    /// `bip39 → bip32(m/44'/144'/0'/0/{i}) → secp256k1 → hash160 →
    /// version 0x00 || payload || double-sha256 checksum → XRPL base58`
    /// using `bip39`, `bip32`, `tiny-secp256k1`, `@cosmjs/crypto` and a
    /// hand-rolled XRPL base58 encoder in Node.js. Any regression in the
    /// derivation or encoding pipeline breaks these fixed strings.
    #[test]
    fn kat_xrpl_abandon_index0() {
        let a = Deriver::new(&wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/144'/0'/0/0");
        assert_eq!(a.address(), "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3");
        assert_eq!(
            a.private_key_hex().as_str(),
            "90802a50aa84efb6cdb225f17c27616ea94048c179142fecf03f4712a07ea7a4"
        );
    }

    #[test]
    fn kat_xrpl_abandon_index1() {
        let a = Deriver::new(&wallet()).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/144'/0'/0/1");
        assert_eq!(a.address(), "r3AgF9mMBFtaLhKcg96weMhbbEFLZ3mx17");
        assert_eq!(
            a.private_key_hex().as_str(),
            "0974b4cfe004a2e6c4364cbf3510a36a352796728d0861f6b555ed7e54a70389"
        );
    }

    /// `derive_many` must return the same accounts as iterating `derive`
    /// individually. Guards against off-by-one and batch/scalar skew.
    #[test]
    fn derive_many_matches_individual() {
        let w = wallet();
        let d = Deriver::new(&w);
        let batch = d.derive_many(0, 3).unwrap();
        let single: Vec<_> = (0..3).map(|i| d.derive(i).unwrap()).collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
        }
    }

    /// A non-empty BIP-39 passphrase must produce a completely different
    /// derivation tree.
    #[test]
    fn passphrase_changes_derivation() {
        let w_no_pw = Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let w_pw = Wallet::from_mnemonic(MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            Deriver::new(&w_no_pw).derive(0).unwrap().address(),
            Deriver::new(&w_pw).derive(0).unwrap().address(),
        );
    }

    /// `derive_path` must honour a fully-qualified path rather than quietly
    /// falling back to the default index.
    #[test]
    fn derive_path_honours_account_segment() {
        let w = wallet();
        let default_addr = Deriver::new(&w).derive(0).unwrap().address().to_owned();
        let alt = Deriver::new(&w).derive_path("m/44'/144'/1'/0/0").unwrap();
        assert_eq!(alt.path(), "m/44'/144'/1'/0/0");
        assert_ne!(alt.address(), default_addr);
    }
}
