//! Filecoin address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec, vec::Vec};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use kobe_primitives::{Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet};

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

    /// Derive at an arbitrary BIP-32 path.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation, `BLAKE2b` hashing, or base32
    /// encoding fails.
    pub fn derive_at(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let key = self.wallet.derive_secp256k1(path)?;
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
            DerivedPublicKey::Secp256k1Uncompressed(pubkey_bytes),
            format!("f1{}", base32_encode(&addr_bytes)?),
        ))
    }
}

impl Derive for Deriver<'_> {
    type Account = DerivedAccount;
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(&format!("m/44'/461'/0'/0/{index}"))
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(path)
    }
}

/// Compute a Blake2b hash with a variable output length.
fn blake2b(data: &[u8], output_len: usize) -> Result<Vec<u8>, DeriveError> {
    let mut hasher = Blake2bVar::new(output_len)
        .map_err(|e| DeriveError::Crypto(format!("blake2b init: {e}")))?;
    hasher.update(data);
    let mut buf = vec![0u8; output_len];
    hasher
        .finalize_variable(&mut buf)
        .map_err(|e| DeriveError::Crypto(format!("blake2b finalize: {e}")))?;
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
            result.push(char::from(*BASE32_ALPHABET.get(index).ok_or_else(
                || {
                    DeriveError::AddressEncoding(String::from(
                        "filecoin base32: index out of range",
                    ))
                },
            )?));
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
        result.push(char::from(*BASE32_ALPHABET.get(index).ok_or_else(
            || DeriveError::AddressEncoding(String::from("filecoin base32: index out of range")),
        )?));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use kobe_primitives::DeriveExt;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    /// RFC 4648 base32 (lower-case, no padding) test vectors from
    /// <https://www.rfc-editor.org/rfc/rfc4648#section-10>, lower-cased and
    /// padding-stripped per the Filecoin address spec.
    #[test]
    fn base32_encode_matches_rfc4648() {
        assert_eq!(base32_encode(b"").unwrap(), "");
        assert_eq!(base32_encode(b"f").unwrap(), "my");
        assert_eq!(base32_encode(b"fo").unwrap(), "mzxq");
        assert_eq!(base32_encode(b"foo").unwrap(), "mzxw6");
        assert_eq!(base32_encode(b"foob").unwrap(), "mzxw6yq");
        assert_eq!(base32_encode(b"fooba").unwrap(), "mzxw6ytb");
        assert_eq!(base32_encode(b"foobar").unwrap(), "mzxw6ytboi");
    }

    /// Known-answer test for the canonical BIP-39 `abandon…about` mnemonic.
    ///
    /// Both address and private key are cross-verified by an independent
    /// pipeline (`bip39 → bip32(m/44'/461'/0'/0/{i}) → secp256k1 →
    /// blake2b-160(uncompressed_pubkey) → checksum = blake2b-32(0x01 ||
    /// payload) → base32-lower(payload || checksum)`) implemented in
    /// Node.js with `bip39`, `bip32`, `tiny-secp256k1`, and
    /// `@noble/hashes` per the Filecoin address spec at
    /// <https://spec.filecoin.io/appendix/address/>.
    #[test]
    fn kat_fil_abandon_index0() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/461'/0'/0/0");
        assert_eq!(a.address(), "f1qode47ievxlxzk6z2viuovedabmn3tq6t57uqhq");
        assert_eq!(
            a.private_key_hex().as_str(),
            "e1808079c6734eff9a187c917455dc1b2c70385e13f1cd6cecc94978e57f7f76"
        );
    }

    #[test]
    fn kat_fil_abandon_index1() {
        let a = Deriver::new(&test_wallet()).derive(1).unwrap();
        assert_eq!(a.path(), "m/44'/461'/0'/0/1");
        assert_eq!(a.address(), "f12nzdrhfh6caurft7gwy6d3uazvgy3lhl7rfzvpq");
        assert_eq!(
            a.private_key_hex().as_str(),
            "ff91cfecbd459ca53112e15c6dd9b26cf4422bb5935c5616d5a6cad95ab0253b"
        );
    }

    /// `derive_many` must agree with scalar `derive` for every index.
    #[test]
    fn derive_many_matches_individual() {
        let w = test_wallet();
        let d = Deriver::new(&w);
        let batch = d.derive_many(0, 3).unwrap();
        let single: Vec<_> = (0..3).map(|i| d.derive(i).unwrap()).collect();
        for (b, s) in batch.iter().zip(single.iter()) {
            assert_eq!(b.address(), s.address());
            assert_eq!(b.path(), s.path());
        }
    }

    /// A non-empty BIP-39 passphrase must produce a different derivation
    /// tree (guards against the passphrase being silently dropped).
    #[test]
    fn passphrase_changes_derivation() {
        let w = Wallet::from_mnemonic(TEST_MNEMONIC, Some("TREZOR")).unwrap();
        assert_ne!(
            Deriver::new(&test_wallet()).derive(0).unwrap().address(),
            Deriver::new(&w).derive(0).unwrap().address(),
        );
    }
}
