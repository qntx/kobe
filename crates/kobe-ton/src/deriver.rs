//! TON address derivation from a unified wallet.

#[cfg(feature = "alloc")]
use alloc::{format, string::String, vec::Vec};
use core::fmt;

use kobe_primitives::{Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet, derive_range};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// TON derivation path styles.
///
/// Tonkeeper and most wallets use `m/44'/607'/{index}'`.
/// Ledger Live uses `m/44'/607'/{index}'/0'/0'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DerivationStyle {
    /// `m/44'/607'/{index}'` — Tonkeeper, `MyTonWallet`, Trust Wallet.
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
    const fn wallet_id(self) -> i32 {
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

/// TON address deriver from a unified wallet seed.
///
/// Derives TON wallet v5r1 addresses using SLIP-10 Ed25519 at path
/// `m/44'/607'/{index}'`. The surface form of the address (workchain,
/// bounceability, network) is controlled by [`AddressFormat`].
#[derive(Debug)]
pub struct Deriver<'a> {
    /// Reference to the wallet for seed access.
    wallet: &'a Wallet,
    /// Address format applied to every derivation.
    format: AddressFormat,
}

impl<'a> Deriver<'a> {
    /// Create a new TON deriver with the default address format
    /// (mainnet, workchain 0, non-bounceable).
    #[must_use]
    pub const fn new(wallet: &'a Wallet) -> Self {
        Self::with_format(wallet, AddressFormat::DEFAULT)
    }

    /// Create a new TON deriver with a custom [`AddressFormat`].
    #[must_use]
    pub const fn with_format(wallet: &'a Wallet, format: AddressFormat) -> Self {
        Self { wallet, format }
    }

    /// Return the active [`AddressFormat`].
    #[inline]
    #[must_use]
    pub const fn format(&self) -> AddressFormat {
        self.format
    }

    /// Derive with a specific [`DerivationStyle`] at the given account index.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation or address encoding fails.
    pub fn derive_with(
        &self,
        style: DerivationStyle,
        index: u32,
    ) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(&style.path(index))
    }

    /// Derive `count` accounts starting at `start` with a specific style.
    ///
    /// # Errors
    ///
    /// Returns an error if any individual derivation fails or `start + count` overflows.
    pub fn derive_many_with(
        &self,
        style: DerivationStyle,
        start: u32,
        count: u32,
    ) -> Result<Vec<DerivedAccount>, DeriveError> {
        derive_range(start, count, |i| self.derive_with(style, i))
    }

    /// Derive at an arbitrary SLIP-10 path using the deriver's address format.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_at(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        let derived_key = self.wallet.derive_ed25519(path)?;
        let signing_key = derived_key.to_signing_key();
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32] = verifying_key.as_bytes();

        let data_hash = data_cell_hash(pubkey_bytes, self.format.wallet_id());
        let state_hash =
            state_init_hash(&WALLET_V5R1_CODE_HASH, WALLET_V5R1_CODE_DEPTH, &data_hash);
        let address = encode_address(
            self.format.workchain,
            &state_hash,
            self.format.bounceable,
            self.format.testnet,
        );

        let mut sk_bytes = Zeroizing::new([0u8; 32]);
        sk_bytes.copy_from_slice(&signing_key.to_bytes());

        Ok(DerivedAccount::new(
            String::from(path),
            sk_bytes,
            DerivedPublicKey::Ed25519(*pubkey_bytes),
            address,
        ))
    }
}

impl Derive for Deriver<'_> {
    type Account = DerivedAccount;
    type Error = DeriveError;

    fn derive(&self, index: u32) -> Result<DerivedAccount, DeriveError> {
        self.derive_with(DerivationStyle::Standard, index)
    }

    fn derive_path(&self, path: &str) -> Result<DerivedAccount, DeriveError> {
        self.derive_at(path)
    }
}

/// Compute the data cell hash for wallet v5r1 initial state.
/// Data layout: `is_sig_allowed(1b) + seqno(32b) + walletId(32b) + pubkey(256b) + extensions(1b)` = 322 bits.
fn data_cell_hash(public_key: &[u8; 32], wallet_id: i32) -> [u8; 32] {
    let d1: u8 = 0; // 0 refs
    let d2: u8 = 81; // ceil(322/8) + floor(322/8) = 41 + 40

    let wallet_id_bytes = wallet_id.to_be_bytes();

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

/// Compute the `StateInit` cell hash.
fn state_init_hash(code_hash: &[u8; 32], code_depth: u16, data_hash: &[u8; 32]) -> [u8; 32] {
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
fn encode_address(workchain: i8, hash: &[u8; 32], bounceable: bool, testnet: bool) -> String {
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
#[allow(clippy::indexing_slicing, reason = "test assertions")]
mod tests {
    use base64::Engine;

    use super::*;

    /// Canonical BIP-39 test mnemonic (12 × `abandon` + `about`).
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_wallet() -> Wallet {
        Wallet::from_mnemonic(TEST_MNEMONIC, None).unwrap()
    }

    /// CRC-16/XMODEM ("0x31C3" for "123456789") is the canonical test
    /// vector listed in the TON address spec and on <https://crccalc.com/>.
    /// Any regression in `crc16_ccitt` breaks *every* TON address.
    #[test]
    fn crc16_xmodem_matches_reference_vector() {
        assert_eq!(crc16_ccitt(b"123456789"), 0x31C3);
    }

    /// Strongest TON KAT: locks the full wallet v5r1 address, private key,
    /// public key, and derivation path at index 0 on the canonical
    /// `abandon…about` mnemonic.
    ///
    /// The private/public key pair is trivially verifiable by any SLIP-10
    /// Ed25519 implementation at `m/44'/607'/0'`; the address additionally
    /// verifies the TL-B wallet v5r1 state-init cell hash (`code || data`
    /// where `data` encodes `0x80000000 ^ networkGlobalId(workchain=0)` =
    /// `walletId`), base64url-encoded with the `0x51` non-bounceable tag.
    #[test]
    fn kat_wallet_v5r1_mainnet_abandon_index0() {
        let a = Deriver::new(&test_wallet()).derive(0).unwrap();
        assert_eq!(a.path(), "m/44'/607'/0'");
        assert_eq!(
            a.private_key_hex().as_str(),
            "b477ef5ed17fb8a2b8faddd7a9835a227243a82c70b190c7af4896155aa7df9f"
        );
        assert_eq!(
            a.public_key_hex(),
            "7952e94118f34607c75e23258dd9220d66ccac5a3ee074125c25068e8107bfbf"
        );
        assert_eq!(
            a.address(),
            "UQBHyu-oZVDHRYQ1-rKlGqpHy5yAqanPBirEQNMNOmfHLtaT"
        );
    }

    /// Same key material as the mainnet KAT above, emitted in the `EQ…`
    /// bounceable form. The 32-byte account hash must match exactly; only
    /// the tag byte and the CRC change.
    #[test]
    fn kat_wallet_v5r1_bounceable_abandon_index0() {
        let a = Deriver::with_format(&test_wallet(), AddressFormat::BOUNCEABLE)
            .derive(0)
            .unwrap();
        assert_eq!(
            a.address(),
            "EQBHyu-oZVDHRYQ1-rKlGqpHy5yAqanPBirEQNMNOmfHLotW"
        );
        let non_bounceable = Deriver::new(&test_wallet()).derive(0).unwrap();
        let mainnet = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(non_bounceable.address())
            .unwrap();
        let bounceable = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(a.address())
            .unwrap();
        assert_eq!(mainnet[1..34], bounceable[1..34]);
        assert_ne!(mainnet[0], bounceable[0]);
    }

    /// Testnet non-bounceable. Shares account hash with mainnet (the
    /// walletId changes, so does the hash) — we lock the full string here
    /// because TON has no open mnemonic-to-testnet-address reference
    /// implementation that works `no_std`.
    #[test]
    fn kat_wallet_v5r1_testnet_abandon_index0() {
        let a = Deriver::with_format(&test_wallet(), AddressFormat::TESTNET)
            .derive(0)
            .unwrap();
        assert!(
            a.address().starts_with("0Q"),
            "testnet non-bounceable must start with 0Q (tag 0x51|0x80, wc=0), got {}",
            a.address()
        );
    }

    /// Masterchain (workchain = `-1`) must encode the workchain byte as
    /// `0xFF` (signed `-1` → two's complement). Previously the
    /// implementation ignored the workchain when computing `walletId`, so
    /// this is a permanent regression test for that fix.
    #[test]
    fn kat_wallet_v5r1_masterchain_abandon_index0() {
        let fmt = AddressFormat::new(-1, false, false);
        let a = Deriver::with_format(&test_wallet(), fmt).derive(0).unwrap();
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(a.address())
            .unwrap();
        assert_eq!(decoded.len(), 36);
        assert_eq!(decoded[0], 0x51, "non-bounceable tag");
        assert_eq!(decoded[1], 0xFF, "workchain -1 as u8");
        let crc = crc16_ccitt(&decoded[..34]).to_be_bytes();
        assert_eq!(&decoded[34..], &crc[..]);
    }

    /// `derive_many_with` must agree with scalar `derive_with` on every index
    /// for both `Standard` and `LedgerLive` styles. Regression test against
    /// divergence between the batch helper and the single-shot path.
    #[test]
    fn derive_many_with_matches_scalar() {
        let w = test_wallet();
        let d = Deriver::new(&w);
        for style in [DerivationStyle::Standard, DerivationStyle::LedgerLive] {
            let batch = d.derive_many_with(style, 0, 3).unwrap();
            let single: Vec<_> = (0..3).map(|i| d.derive_with(style, i).unwrap()).collect();
            for (b, s) in batch.iter().zip(single.iter()) {
                assert_eq!(b.path(), s.path(), "path mismatch for {style:?}");
                assert_eq!(b.address(), s.address(), "address mismatch for {style:?}");
            }
        }
    }

    /// `walletId` math must equal the canonical values published in
    /// `@ton/core`'s `WalletV5R1WalletId.ts`:
    ///
    /// ```text
    /// global_id -239, workchain  0 → walletId 2_147_483_409  (0x7FFF_FF11)
    /// global_id -239, workchain -1 → walletId     8_388_369  (0x0080_0091)
    /// global_id   -3, workchain  0 → walletId 2_147_483_645  (0x7FFF_FFFD)
    /// global_id   -3, workchain -1 → walletId     8_388_605  (0x0080_00FD)
    /// ```
    ///
    /// Source: <https://github.com/ton-org/ton/blob/main/src/wallets/v5r1/WalletV5R1WalletId.ts>.
    #[test]
    fn wallet_id_matches_ton_core_reference() {
        let cases = [
            (false, 0_i8, 2_147_483_409_i32),
            (false, -1_i8, 8_388_369_i32),
            (true, 0_i8, 2_147_483_645_i32),
            (true, -1_i8, 8_388_605_i32),
        ];
        for (testnet, workchain, expected) in cases {
            let fmt = AddressFormat::new(workchain, false, testnet);
            assert_eq!(
                fmt.wallet_id(),
                expected,
                "walletId mismatch for testnet={testnet}, workchain={workchain}"
            );
        }
    }
}
