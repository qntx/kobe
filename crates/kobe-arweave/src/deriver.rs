//! Arweave ECDSA address derivation from a unified wallet.
//!
//! ## Address algorithm (protocol + `arweave-js` `master-ec`)
//!
//! 1. Derive a secp256k1 key pair at `m/44'/472'/0'/0/{index}` (SLIP-44 coin 472).
//! 2. Take the **33-byte compressed** public key (`ECDSA_PUB_KEY_SIZE` in
//!    `ar.hrl`; `compress_ecdsa_pubkey/1` in `ar_wallet.erl`;
//!    `SECP256K1_IDENTIFIER_SIZE` in `arweave-js`).
//! 3. `SHA-256(compressed_pubkey)` → 32 bytes.
//! 4. Encode with [`Base64URL`] without padding into a 43-character address string.
//!
//! [`Base64URL`]: https://datatracker.ietf.org/doc/html/rfc4648#section-5
//!
//! This is **not** an Ethereum address (no Keccak-256 truncation). Hashing the
//! uncompressed 65-byte SEC1 point yields a different address and is wrong.
//!
//! Signing (65-byte recoverable ECDSA, empty `owner`, format=2) belongs in a
//! companion signer crate, not here.

#[cfg(feature = "alloc")]
use alloc::{format, string::String};

use base64::Engine;
use kobe_primitives::{Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet};
use sha2::{Digest, Sha256};

/// Encode a compressed secp256k1 public key as an Arweave address.
///
/// `Base64URL_nopad(SHA-256(pk))` — same preimage as the node for ECDSA wallets.
#[must_use]
pub fn address_from_compressed_pubkey(pk: &[u8; 33]) -> String {
    let digest = Sha256::digest(pk);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Encode a compressed public key as the recovered ECDSA **owner** string.
///
/// On format-2 ECDSA transactions the `owner` field is empty and clients
/// recover this value (`Base64URL` of the 33-byte identifier), not the account address.
#[must_use]
pub fn owner_from_compressed_pubkey(pk: &[u8; 33]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk)
}

/// Arweave ECDSA address deriver.
///
/// Uses BIP-44 coin type 472 with secp256k1. RSA is not supported.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Wallet seed reference.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create an Arweave ECDSA deriver.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive at an arbitrary BIP-32 path.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_at(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
        let pubkey_bytes = key.compressed_pubkey();
        let address = address_from_compressed_pubkey(&pubkey_bytes);

        Ok(DerivedAccount::new(
            path.into(),
            key.private_key_bytes(),
            DerivedPublicKey::Secp256k1Compressed(pubkey_bytes),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Account = DerivedAccount;
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        let path = format!("m/44'/472'/0'/0/{index}");
        self.derive_at(&path)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(path)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn wallet() -> Wallet {
        Wallet::from_mnemonic(MNEMONIC, None).unwrap()
    }

    /// Known-answer: BIP-39 abandon → BIP-32 `m/44'/472'/0'/0/0` → compressed pk
    /// → Base64URL(SHA-256). Cross-checked with `@scure/bip32` + `@noble/hashes`.
    #[test]
    fn kat_arweave_abandon_index0() {
        let a = Deriver::new(&wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/472'/0'/0/0");
        assert_eq!(a.address(), "G3y00z9F3EvSzJprpIH6vPqHVZPH0rLqLrg0JOsd88Y");
        assert_eq!(
            a.private_key_hex().as_str(),
            "130721c87ce0ace0999c94a5943d055b224411eda752680ca24969d0837ff152"
        );
        assert_eq!(a.address().len(), 43);
    }

    #[test]
    fn kat_arweave_abandon_index1() {
        let a = Deriver::new(&wallet()).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/472'/0'/0/1");
        assert_eq!(a.address(), "s67JULQPjY6wpxYV4imfx_Ui6twtC_jfxnluJT4GOSo");
        assert_eq!(
            a.private_key_hex().as_str(),
            "a8822ffcffba36d726f8ddd866963325b668c36d780f73fcf245a59babd8aa12"
        );
    }

    #[test]
    fn address_from_compressed_pubkey_matches_kat() {
        let key = wallet().derive_secp256k1("m/44'/472'/0'/0/0").unwrap();
        let pk = key.compressed_pubkey();
        assert_eq!(
            key.compressed_pubkey_hex(),
            "03df9a82774ebbcd956bb1bd8a7851f25a95dcb11b064a74ccadcf277ccb6d3b6f"
        );
        assert_eq!(
            address_from_compressed_pubkey(&pk),
            "G3y00z9F3EvSzJprpIH6vPqHVZPH0rLqLrg0JOsd88Y"
        );
    }

    #[test]
    fn owner_from_compressed_pubkey_index0() {
        let key = wallet().derive_secp256k1("m/44'/472'/0'/0/0").unwrap();
        assert_eq!(
            owner_from_compressed_pubkey(&key.compressed_pubkey()),
            "A9-agndOu82Va7G9inhR8lqV3LEbBkp0zK3PJ3zLbTtv"
        );
    }

    /// Hashing the uncompressed SEC1 point must not produce the protocol address.
    #[test]
    fn uncompressed_pubkey_yields_different_address() {
        let key = wallet().derive_secp256k1("m/44'/472'/0'/0/0").unwrap();
        let compressed = key.compressed_pubkey();
        let uncompressed = key.uncompressed_pubkey();
        let wrong = {
            let digest = Sha256::digest(uncompressed);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        };
        assert_ne!(address_from_compressed_pubkey(&compressed), wrong);
        assert_eq!(
            wrong.as_str(),
            "eOqGD0loQiFvP7w-aQNq1DoVyTJM_eUnPG78vKY3JIM"
        );
    }

    #[test]
    fn address_charset_and_length() {
        let a = Deriver::new(&wallet()).derive(0).unwrap();
        assert_eq!(a.address().len(), 43);
        assert!(
            a.address()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

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

    #[test]
    fn passphrase_changes_derivation() {
        let w_no_pw = Wallet::from_mnemonic(MNEMONIC, None).unwrap();
        let w_pw = Wallet::from_mnemonic(MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            Deriver::new(&w_no_pw).derive(0).unwrap().address(),
            Deriver::new(&w_pw).derive(0).unwrap().address(),
        );
    }

    #[test]
    fn derive_path_honours_account_segment() {
        let w = wallet();
        let default_addr = Deriver::new(&w).derive(0).unwrap().address().to_owned();
        let alt = Deriver::new(&w).derive_path("m/44'/472'/1'/0/0").unwrap();
        assert_eq!(alt.path(), "m/44'/472'/1'/0/0");
        assert_ne!(alt.address(), default_addr);
    }
}
