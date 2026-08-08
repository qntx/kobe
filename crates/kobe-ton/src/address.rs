//! TON address encoding (wallet v5r1 state-init + user-friendly form).

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// Wallet v5r1 code cell hash (SHA256 of the cell representation).
pub(crate) const WALLET_V5R1_CODE_HASH: [u8; 32] = [
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
];

/// Wallet v5r1 code cell depth.
pub(crate) const WALLET_V5R1_CODE_DEPTH: u16 = 6;

/// TON mainnet global id (`-239`).
const NETWORK_GLOBAL_ID_MAINNET: i32 = -239;

/// TON testnet global id (`-3`).
const NETWORK_GLOBAL_ID_TESTNET: i32 = -3;

/// User-friendly TON address format configuration.
///
/// Controls the workchain, bounceability, and network (mainnet/testnet) of
/// the generated address without affecting the underlying key derivation.
///
/// # Defaults
///
/// - Workchain `0` (basechain)
/// - Non-bounceable (`UQ…` on mainnet)
/// - Mainnet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AddressFormat {
    /// Workchain ID; `0` = basechain, `-1` = masterchain.
    pub workchain: i8,
    /// Whether to emit a *bounceable* (`EQ…` / `kQ…`) address.
    ///
    /// Tonkeeper and most modern wallets prefer **non-bounceable** (`UQ…` /
    /// `0Q…`) for plain wallets. Smart-contract destinations typically use
    /// bounceable.
    pub bounceable: bool,
    /// Testnet flag; toggles the `0x80` bit in the address tag and selects
    /// the testnet walletId variant for v5r1.
    pub testnet: bool,
}

impl AddressFormat {
    /// Default mainnet, workchain 0, non-bounceable format (`UQ…`).
    pub const DEFAULT: Self = Self {
        workchain: 0,
        bounceable: false,
        testnet: false,
    };

    /// Mainnet, workchain 0, bounceable (`EQ…`).
    pub const BOUNCEABLE: Self = Self {
        workchain: 0,
        bounceable: true,
        testnet: false,
    };

    /// Testnet, workchain 0, non-bounceable (`0Q…`).
    pub const TESTNET: Self = Self {
        workchain: 0,
        bounceable: false,
        testnet: true,
    };

    /// Construct a custom format.
    #[must_use]
    pub const fn new(workchain: i8, bounceable: bool, testnet: bool) -> Self {
        Self {
            workchain,
            bounceable,
            testnet,
        }
    }

    /// Return the walletId v5r1 derives for this network + workchain.
    ///
    /// Matches the `WalletV5R1WalletId` serialization used by `@ton/core`:
    /// `walletId = networkGlobalId ^ clientContext(workchain, version=0, subwallet=0)`.
    /// Verified against canonical values (e.g. mainnet workchain 0 →
    /// `2147483409`; testnet workchain 0 → `2147483645`; mainnet workchain
    /// -1 → `8388369`; testnet workchain -1 → `8388605`).
    pub(crate) const fn wallet_id(self) -> i32 {
        let global_id = if self.testnet {
            NETWORK_GLOBAL_ID_TESTNET
        } else {
            NETWORK_GLOBAL_ID_MAINNET
        };
        global_id ^ encode_client_context(self.workchain)
    }
}

/// Encode the 32-bit v5r1 *client* context:
/// `[is_client:1 = 1][workchain:i8][wallet_version:u8 = 0][subwallet:u15 = 0]`.
///
/// Bit-level layout (MSB-first):
/// - bit 0:        1 (client context flag)
/// - bits 1..=8:   workchain as signed 8-bit (two's complement)
/// - bits 9..=16:  `wallet_version` = 0
/// - bits 17..=31: `subwallet_number` = 0
const fn encode_client_context(workchain: i8) -> i32 {
    let wc_byte = workchain.to_ne_bytes()[0] as u32;
    let bits = 0x8000_0000_u32 | (wc_byte << 23);
    i32::from_be_bytes(bits.to_be_bytes())
}

impl Default for AddressFormat {
    #[inline]
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Compute the data cell hash for wallet v5r1 initial state.
///
/// Data layout (322 bits, MSB-first):
/// `is_sig_allowed(1) || seqno(32) || walletId(32) || pubkey(256) || extensions(1)`.
///
/// Serializes through [`BitWriter`] so the non-byte-aligned completion tag
/// is handled declaratively instead of via hand-rolled bit arrays.
pub(crate) fn data_cell_hash(public_key: &[u8; 32], wallet_id: i32) -> [u8; 32] {
    /// Total payload bit length for the wallet v5r1 data cell.
    const DATA_BITS: usize = 322;
    /// TL-B cell descriptor `d1`: `refs << 1` (0 refs for this leaf cell).
    const D1: u8 = 0;
    /// TL-B cell descriptor `d2`: `ceil(bits/8) + floor(bits/8)` = 41 + 40.
    const D2: u8 = 81;

    // Compile-time lock: keep `D2` honest against `DATA_BITS`.
    const _: () = assert!(
        DATA_BITS.div_ceil(8) + DATA_BITS / 8 == D2 as usize,
        "TL-B d2 descriptor must equal ceil(bits/8) + floor(bits/8)"
    );

    let mut writer = BitWriter::with_bit_capacity(DATA_BITS);
    writer.push_bit(true); // is_signature_allowed = 1
    writer.push_u32_be(0); // seqno = 0
    writer.push_i32_be(wallet_id); // walletId (big-endian, two's complement)
    writer.push_bytes(public_key); // 256-bit Ed25519 public key
    writer.push_bit(false); // extensions = 0 (empty dict)

    let (data_bytes, bit_len) = writer.finalize_with_completion_tag();
    debug_assert_eq!(
        bit_len, DATA_BITS,
        "wallet v5r1 data cell must serialize to exactly {DATA_BITS} bits"
    );

    let mut repr = Vec::with_capacity(2 + data_bytes.len());
    repr.push(D1);
    repr.push(D2);
    repr.extend_from_slice(&data_bytes);

    Sha256::digest(&repr).into()
}

/// Streaming MSB-first bit writer for TL-B cell serialization.
///
/// Tracks the write cursor in units of bits; `finalize_with_completion_tag`
/// appends the `1`-then-zero-padding tag required by TL-B whenever the
/// final bit count is not byte-aligned.
pub(crate) struct BitWriter {
    bytes: Vec<u8>,
    /// Number of bits already written into the tail byte (`bytes.last()`);
    /// always `0..8`. Zero means the next write starts a fresh byte.
    tail_bits: u8,
}

impl BitWriter {
    /// Create a writer with capacity for at least `bits` bits of output.
    pub(crate) fn with_bit_capacity(bits: usize) -> Self {
        Self {
            // Reserve one extra byte for the completion tag worst case.
            bytes: Vec::with_capacity(bits.div_ceil(8) + 1),
            tail_bits: 0,
        }
    }

    /// Append a single bit.
    pub(crate) fn push_bit(&mut self, bit: bool) {
        if self.tail_bits == 0 {
            self.bytes.push(if bit { 0x80 } else { 0 });
        } else if bit {
            debug_assert!(
                !self.bytes.is_empty(),
                "BitWriter invariant: tail_bits > 0 implies at least one byte exists"
            );
            if let Some(last) = self.bytes.last_mut() {
                *last |= 1u8 << (7 - self.tail_bits);
            }
        }
        self.tail_bits = (self.tail_bits + 1) & 0x07;
    }

    /// Append a whole byte (8 MSB-first bits). Preserves `tail_bits`.
    pub(crate) fn push_byte(&mut self, b: u8) {
        if self.tail_bits == 0 {
            self.bytes.push(b);
            return;
        }
        let shift = self.tail_bits;
        debug_assert!(
            !self.bytes.is_empty(),
            "BitWriter invariant: tail_bits > 0 implies at least one byte exists"
        );
        if let Some(last) = self.bytes.last_mut() {
            *last |= b >> shift;
        }
        self.bytes.push(b << (8 - shift));
    }

    /// Append the big-endian encoding of a `u32`.
    pub(crate) fn push_u32_be(&mut self, v: u32) {
        for &b in &v.to_be_bytes() {
            self.push_byte(b);
        }
    }

    /// Append the big-endian encoding of an `i32` (two's complement).
    pub(crate) fn push_i32_be(&mut self, v: i32) {
        for &b in &v.to_be_bytes() {
            self.push_byte(b);
        }
    }

    /// Append each byte of `data` in order.
    pub(crate) fn push_bytes(&mut self, data: &[u8]) {
        for &b in data {
            self.push_byte(b);
        }
    }

    /// Bit-level length of the payload *before* the completion tag.
    pub(crate) fn bit_len(&self) -> usize {
        if self.tail_bits == 0 {
            self.bytes.len() * 8
        } else {
            (self.bytes.len() - 1) * 8 + usize::from(self.tail_bits)
        }
    }

    /// Return `(bytes, payload_bit_len)` with the TL-B completion tag
    /// appended iff the payload is not already byte-aligned.
    pub(crate) fn finalize_with_completion_tag(mut self) -> (Vec<u8>, usize) {
        let bit_len = self.bit_len();
        if self.tail_bits != 0 {
            self.push_bit(true);
            while self.tail_bits != 0 {
                self.push_bit(false);
            }
        }
        (self.bytes, bit_len)
    }
}

/// Compute the `StateInit` cell hash.
pub(crate) fn state_init_hash(
    code_hash: &[u8; 32],
    code_depth: u16,
    data_hash: &[u8; 32],
) -> [u8; 32] {
    let d1: u8 = 2; // 2 refs
    let d2: u8 = 1; // ceil(5/8) + floor(5/8) = 1 + 0

    let mut repr = Vec::with_capacity(3 + 4 + 64);
    repr.push(d1);
    repr.push(d2);
    repr.push(0x34); // 00110 + completion tag '100' = 0b00110100

    // Depths (2 bytes big-endian each)
    let depth_bytes = code_depth.to_be_bytes();
    repr.push(depth_bytes[0]);
    repr.push(depth_bytes[1]);
    repr.push(0); // data cell depth = 0
    repr.push(0);

    repr.extend_from_slice(code_hash);
    repr.extend_from_slice(data_hash);

    Sha256::digest(&repr).into()
}

/// Encode a TON user-friendly address (base64url with CRC16).
pub(crate) fn encode_address(
    workchain: i8,
    hash: &[u8; 32],
    bounceable: bool,
    testnet: bool,
) -> String {
    use base64::Engine;

    let base: u8 = if bounceable { 0x11 } else { 0x51 };
    let tag: u8 = if testnet { base | 0x80 } else { base };
    let mut addr = Vec::with_capacity(36);
    addr.push(tag);
    addr.push(workchain.to_ne_bytes()[0]);
    addr.extend_from_slice(hash);

    let crc = crc16_ccitt(&addr);
    let crc_bytes = crc.to_be_bytes();
    addr.push(crc_bytes[0]);
    addr.push(crc_bytes[1]);

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&addr)
}

/// CRC16-CCITT (initial value 0, polynomial 0x1021).
pub(crate) fn crc16_ccitt(data: &[u8]) -> u16 {
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
