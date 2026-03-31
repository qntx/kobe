//! TON address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use ed25519_dalek::VerifyingKey;
pub use kobe_core::DerivedAccount;
use kobe_core::slip10::DerivedKey;
use kobe_core::{Derive, Wallet};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

/// TON derivation path styles.
///
/// Tonkeeper and most wallets use `m/44'/607'/{index}'`.
/// Ledger Live uses `m/44'/607'/{index}'/0'/0'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// `m/44'/607'/{index}'` — Tonkeeper, MyTonWallet, Trust Wallet.
    #[default]
    Standard,
    /// `m/44'/607'/{index}'/0'/0'` — Ledger Live.
    LedgerLive,
}

impl DerivationStyle {
    /// Build the derivation path string for a given index.
    #[must_use]
    pub fn path(self, index: u32) -> String {
        match self {
            Self::Standard => format!("m/44'/607'/{index}'"),
            Self::LedgerLive => format!("m/44'/607'/{index}'/0'/0'"),
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Standard => "Standard (Tonkeeper)",
            Self::LedgerLive => "Ledger Live",
        }
    }
}

impl fmt::Display for DerivationStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Wallet v5r1 code cell hash (SHA256 of the cell representation).
const WALLET_V5R1_CODE_HASH: [u8; 32] = [
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
];

/// Wallet v5r1 code cell depth.
const WALLET_V5R1_CODE_DEPTH: u16 = 6;

/// Default walletId for mainnet workchain 0.
/// Computed as: `networkGlobalId(-239) XOR context(0x80000000)`
#[allow(clippy::cast_possible_wrap)]
const DEFAULT_WALLET_ID: i32 = 0x7FFF_FF11_u32 as i32;

/// TON address deriver from a unified wallet seed.
///
/// Derives TON wallet v5r1 addresses using SLIP-10 Ed25519 at path `m/44'/607'/{index}'`.
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
}

impl<'a> Deriver<'a> {
    /// Create a new TON deriver from a wallet.
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self { wallet }
    }

    /// Derive with a specific [`DerivationStyle`].
    pub fn derive_with(&self, style: DerivationStyle, index: u32) -> Result<DerivedAccount, Error> {
        self.derive_at_path(&style.path(index))
    }

    /// Internal: derive at an arbitrary SLIP-10 path.
    fn derive_at_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        let derived_key = DerivedKey::derive_path(self.wallet.seed(), path)?;
        let signing_key = derived_key.to_signing_key();
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32] = verifying_key.as_bytes();

        let data_hash = data_cell_hash(pubkey_bytes);
        let state_hash =
            state_init_hash(&WALLET_V5R1_CODE_HASH, WALLET_V5R1_CODE_DEPTH, &data_hash);
        let address = encode_address(0, &state_hash, false);

        Ok(DerivedAccount::new(
            path.to_string(),
            Zeroizing::new(hex::encode(signing_key.to_bytes())),
            hex::encode(pubkey_bytes),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Error = Error;

    fn derive(&self, index: u32) -> Result<DerivedAccount, Error> {
        self.derive_with(DerivationStyle::Standard, index)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, Error> {
        self.derive_at_path(path)
    }
}

/// Compute the data cell hash for wallet v5r1 initial state.
/// Data layout: `is_sig_allowed(1b) + seqno(32b) + walletId(32b) + pubkey(256b) + extensions(1b)` = 322 bits.
fn data_cell_hash(public_key: &[u8; 32]) -> [u8; 32] {
    let d1: u8 = 0; // 0 refs
    let d2: u8 = 81; // ceil(322/8) + floor(322/8) = 41 + 40

    let wallet_id_bytes = DEFAULT_WALLET_ID.to_be_bytes();

    // Pack 322 bits: [1-bit flag][32-bit seqno][32-bit walletId][256-bit key][1-bit ext]
    let mut bits = Vec::with_capacity(328);
    bits.push(1u8); // is_signature_allowed = 1
    bits.extend(core::iter::repeat_n(0u8, 32)); // seqno = 0
    for &b in &wallet_id_bytes {
        for shift in (0..8).rev() {
            bits.push((b >> shift) & 1);
        }
    }
    for &b in public_key {
        for shift in (0..8).rev() {
            bits.push((b >> shift) & 1);
        }
    }
    bits.push(0); // extensions = 0

    // Completion tag: 1 followed by zeros to fill the byte
    bits.push(1);
    while bits.len() % 8 != 0 {
        bits.push(0);
    }

    // Convert bit array to bytes
    let mut data_bytes = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            byte |= bit << (7 - i);
        }
        data_bytes.push(byte);
    }

    let mut repr = Vec::with_capacity(2 + data_bytes.len());
    repr.push(d1);
    repr.push(d2);
    repr.extend_from_slice(&data_bytes);

    Sha256::digest(&repr).into()
}

/// Compute the StateInit cell hash.
fn state_init_hash(code_hash: &[u8; 32], code_depth: u16, data_hash: &[u8; 32]) -> [u8; 32] {
    let d1: u8 = 2; // 2 refs
    let d2: u8 = 1; // ceil(5/8) + floor(5/8) = 1 + 0

    let mut repr = Vec::with_capacity(3 + 4 + 64);
    repr.push(d1);
    repr.push(d2);
    repr.push(0x34); // 00110 + completion tag '100' = 0b00110100

    // Depths (2 bytes big-endian each)
    #[allow(clippy::cast_possible_truncation)]
    repr.push((code_depth >> 8) as u8);
    #[allow(clippy::cast_possible_truncation)]
    repr.push(code_depth as u8);
    repr.push(0); // data cell depth = 0
    repr.push(0);

    repr.extend_from_slice(code_hash);
    repr.extend_from_slice(data_hash);

    Sha256::digest(&repr).into()
}

/// Encode a TON user-friendly address (base64url with CRC16).
fn encode_address(workchain: i8, hash: &[u8; 32], bounceable: bool) -> String {
    use base64::Engine;

    let tag: u8 = if bounceable { 0x11 } else { 0x51 };
    let mut addr = Vec::with_capacity(36);
    addr.push(tag);
    #[allow(clippy::cast_sign_loss)]
    addr.push(workchain as u8);
    addr.extend_from_slice(hash);

    let crc = crc16_ccitt(&addr);
    #[allow(clippy::cast_possible_truncation)]
    addr.push((crc >> 8) as u8);
    #[allow(clippy::cast_possible_truncation)]
    addr.push(crc as u8);

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&addr)
}

/// CRC16-CCITT (initial value 0, polynomial 0x1021).
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    #[test]
    fn derive_starts_with_uq() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert!(
            derived.address.starts_with("UQ"),
            "non-bounceable address should start with UQ, got: {}",
            derived.address
        );
    }

    #[test]
    fn derive_address_length() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.address.len(), 48);
    }

    #[test]
    fn derive_correct_path() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(derived.path, "m/44'/607'/0'");
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
    fn address_decodes_to_valid_structure() {
        use base64::Engine;
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&derived.address)
            .unwrap();
        assert_eq!(decoded.len(), 36);
        assert_eq!(decoded[0], 0x51); // non-bounceable
        assert_eq!(decoded[1], 0x00); // workchain 0

        let crc = crc16_ccitt(&decoded[..34]);
        assert_eq!(decoded[34], (crc >> 8) as u8);
        assert_eq!(decoded[35], crc as u8);
    }

    #[test]
    fn kat_known_keys_index0() {
        let wallet = test_wallet();
        let derived = Deriver::new(&wallet).derive(0).unwrap();
        assert_eq!(
            derived.private_key.as_str(),
            "b477ef5ed17fb8a2b8faddd7a9835a227243a82c70b190c7af4896155aa7df9f"
        );
        assert_eq!(
            derived.public_key,
            "7952e94118f34607c75e23258dd9220d66ccac5a3ee074125c25068e8107bfbf"
        );
    }

    #[test]
    fn crc16_known_vector() {
        assert_eq!(crc16_ccitt(b"123456789"), 0x31C3);
    }
}
