//! TL-B cell serialization and hashing behind TON wallet state-init hashes.

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::Error;

/// `SHA-256` of a `StateInit` cell: `refs=2, 5-bit body, depths, hashes`.
pub(super) fn state_init_hash(
    code_hash: &[u8; 32],
    code_depth: u16,
    data_hash: &[u8; 32],
) -> [u8; 32] {
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
pub(super) fn data_cell_hash(
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
