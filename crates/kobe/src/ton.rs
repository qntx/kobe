//! TON (The Open Network): SLIP-10 ed25519 derivation, coin type 607.
//!
//! Addresses are the user-friendly base64url form of the wallet contract
//! state-init hash for `V4R2` (default) or `V5R1`, matching `@ton/ton`'s
//! `WalletContractV4`/`WalletContractV5R1` exactly: subwallet id
//! `698983191 + workchain` for V4R2, `networkGlobalId ^ clientContext` for
//! V5R1. The address tag carries the bounceable and testnet-only flags.
//! `private_key` is the raw 32-byte SLIP-10 seed as hex.

use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::encoding::secret::hex_secret;
use crate::hd::slip10;
use crate::{Account, Chain, DerivationPath, Error, SecretKey, Style, Wallet};

/// V4R2 wallet code cell hash (@ton/ton `WalletContractV4` code).
const V4R2_CODE_HASH: [u8; 32] = [
    0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d,
    0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8, 0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0,
];
/// V4R2 wallet code cell depth.
const V4R2_CODE_DEPTH: u16 = 7;
/// V4R2 base subwallet id; the effective id adds the workchain.
const V4R2_SUBWALLET_BASE: u32 = 698_983_191;

/// V5R1 wallet code cell hash (@ton/ton `WalletContractV5R1` code).
const V5R1_CODE_HASH: [u8; 32] = [
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
];
/// V5R1 wallet code cell depth.
const V5R1_CODE_DEPTH: u16 = 6;
/// TON network global ids used to derive the V5R1 wallet id.
const GLOBAL_ID_MAINNET: i32 = -239;
const GLOBAL_ID_TESTNET: i32 = -3;

crate::option_enum! {
    /// TON wallet contract version.
    pub enum Contract {
        /// Wallet V4R2 (subwallet `698983191 + workchain`).
        #[default]
        V4r2 = "v4r2",
        /// Wallet V5R1 (`networkGlobalId ^ clientContext` wallet id).
        V5r1 = "v5r1",
    }
}

/// The TON chain.
///
/// Only workchain `0` (basechain) is emitted; `testnet` toggles both the
/// address's testnet-only flag and the V5R1 network global id.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ton {
    /// Wallet contract version.
    pub contract: Contract,
    /// Testnet flag (`0Q…`/`kQ…` addresses, V5R1 global id `-3`).
    pub testnet: bool,
    /// Bounceable flag (`EQ…`/`kQ…` addresses; default non-bounceable).
    pub bounceable: bool,
}

impl Ton {
    /// A `Ton` chain for `contract` on mainnet, non-bounceable.
    #[must_use]
    pub const fn new(contract: Contract) -> Self {
        Self {
            contract,
            testnet: false,
            bounceable: false,
        }
    }
}

impl Chain for Ton {
    fn styles(&self) -> Vec<Style> {
        Vec::from([
            Style::new("standard", "m/44'/607'/{i}'", "OneKey"),
            Style::new("ledger-live", "m/44'/607'/0'/0'/{i}'/0'", "Ledger Live"),
        ])
    }

    fn derive(&self, wallet: &Wallet, path: &DerivationPath) -> Result<Account, Error> {
        let node = slip10::Node::derive(wallet.seed(), path)?;
        let secret = node.secret_key();
        let public_key = node.public_key();

        // One data-cell shape for both contracts: V5R1 prepends the
        // `is_signature_allowed` bit and swaps subwallet for its wallet id.
        let (code_hash, code_depth, signature_allowed, wallet_id) = match self.contract {
            Contract::V4r2 => (
                &V4R2_CODE_HASH,
                V4R2_CODE_DEPTH,
                false,
                V4R2_SUBWALLET_BASE.cast_signed(),
            ),
            Contract::V5r1 => (
                &V5R1_CODE_HASH,
                V5R1_CODE_DEPTH,
                true,
                self.wallet_id_v5r1(),
            ),
        };
        let data_hash = data_cell_hash(signature_allowed, wallet_id, &public_key)?;
        let account_hash = state_init_hash(code_hash, code_depth, &data_hash);
        let address = encode_address(&account_hash, self.bounceable, self.testnet);

        Ok(Account::new(
            path.clone(),
            address,
            hex::encode(public_key),
            hex_secret(secret.as_slice()),
            SecretKey::Ed25519(secret),
        ))
    }
}

impl Ton {
    /// V5R1 `walletId = networkGlobalId ^ clientContext(workchain, 0, 0)`.
    /// For workchain 0 the client context is `0x80000000`, matching
    /// `@ton/ton` (`-239/-3 → 2147483409/2147483645` on basechain).
    const fn wallet_id_v5r1(self) -> i32 {
        let global_id = if self.testnet {
            GLOBAL_ID_TESTNET
        } else {
            GLOBAL_ID_MAINNET
        };
        global_id ^ i32::from_be_bytes(0x8000_0000u32.to_be_bytes())
    }
}

/// `SHA-256` of a `StateInit` cell: `refs=2, 5-bit body, depths, hashes`.
fn state_init_hash(code_hash: &[u8; 32], code_depth: u16, data_hash: &[u8; 32]) -> [u8; 32] {
    let mut repr = Vec::with_capacity(3 + 4 + 64);
    repr.push(2); // d1: 2 refs
    repr.push(1); // d2: ceil(5/8)+floor(5/8)
    repr.push(0x34); // body: `code? data? = 00110` + completion tag
    repr.extend_from_slice(&code_depth.to_be_bytes());
    repr.extend_from_slice(&[0, 0]); // data cell depth 0
    repr.extend_from_slice(code_hash);
    repr.extend_from_slice(data_hash);
    Sha256::digest(&repr).into()
}

/// `SHA-256` of a leaf cell's repr: `d1=0 ‖ d2 ‖ tagged bytes`.
fn leaf_cell_hash(bytes: &[u8], bits: usize) -> Result<[u8; 32], Error> {
    let d2 = u8::try_from(bits.div_ceil(8) + bits / 8)
        .map_err(|_| Error::InvalidKey(String::from("cell descriptor out of range")))?;
    let mut repr = Vec::with_capacity(2 + bytes.len());
    repr.push(0); // d1: no refs
    repr.push(d2);
    repr.extend_from_slice(bytes);
    Ok(Sha256::digest(&repr).into())
}

/// Wallet data cell: `[is_signature_allowed(1)] ‖ seqno(32) ‖
/// wallet/subwallet id(32) ‖ pubkey(256) ‖ extensions-empty(1)`.
fn data_cell_hash(
    signature_allowed: bool,
    wallet_id: i32,
    public_key: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let mut writer = BitWriter::new();
    if signature_allowed {
        writer.push_bit(true);
    }
    for &b in &0u32.to_be_bytes() {
        writer.push_byte(b);
    }
    for &b in &wallet_id.to_be_bytes() {
        writer.push_byte(b);
    }
    for &b in public_key {
        writer.push_byte(b);
    }
    writer.push_bit(false); // extensions dict: empty
    let (bytes, bits) = writer.finalize();
    leaf_cell_hash(&bytes, bits)
}

/// Streaming MSB-first bit writer for TL-B cell serialization.
struct BitWriter {
    bytes: Vec<u8>,
    tail_bits: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(42),
            tail_bits: 0,
        }
    }

    fn push_bit(&mut self, bit: bool) {
        if self.tail_bits == 0 {
            self.bytes.push(if bit { 0x80 } else { 0 });
        } else if bit && let Some(last) = self.bytes.last_mut() {
            *last |= 1u8 << (7 - self.tail_bits);
        }
        self.tail_bits = (self.tail_bits + 1) & 0x07;
    }

    fn push_byte(&mut self, b: u8) {
        if self.tail_bits == 0 {
            self.bytes.push(b);
            return;
        }
        let shift = self.tail_bits;
        if let Some(last) = self.bytes.last_mut() {
            *last |= b >> shift;
        }
        self.bytes.push(b << (8 - shift));
    }

    /// Append the TL-B completion tag iff the payload is not byte-aligned;
    /// returns the bytes and the pre-tag payload bit length.
    fn finalize(mut self) -> (Vec<u8>, usize) {
        let bit_len = if self.tail_bits == 0 {
            self.bytes.len() * 8
        } else {
            (self.bytes.len() - 1) * 8 + usize::from(self.tail_bits)
        };
        if self.tail_bits != 0 {
            self.push_bit(true);
            while self.tail_bits != 0 {
                self.push_bit(false);
            }
        }
        (self.bytes, bit_len)
    }
}

/// Encode a TON user-friendly address: `base64url(tag ‖ wc ‖ hash ‖ crc16)`.
fn encode_address(hash: &[u8; 32], bounceable: bool, testnet: bool) -> String {
    let base: u8 = if bounceable { 0x11 } else { 0x51 };
    let tag: u8 = if testnet { base | 0x80 } else { base };
    let mut addr = Vec::with_capacity(36);
    addr.push(tag);
    addr.push(0); // workchain 0 (basechain)
    addr.extend_from_slice(hash);

    let crc = crc::Crc::<u16>::new(&crc::CRC_16_XMODEM).checksum(&addr);
    addr.extend_from_slice(&crc.to_be_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&addr)
}
