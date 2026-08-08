//! TON address derivation from a unified wallet.

use alloc::string::String;
use alloc::vec::Vec;

use kobe_primitives::{
    DerivationStyle as _, Derive, DeriveError, DerivedAccount, DerivedPublicKey, Wallet,
    derive_range,
};
use zeroize::Zeroizing;

use crate::address::{
    AddressFormat, WALLET_V5R1_CODE_DEPTH, WALLET_V5R1_CODE_HASH, data_cell_hash, encode_address,
    state_init_hash,
};
#[cfg(test)]
use crate::address::{BitWriter, crc16_ccitt};
use crate::style::DerivationStyle;

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

    /// Byte-aligned writes must produce the input byte stream verbatim and
    /// never append a completion tag (TL-B only pads non-aligned cells).
    #[test]
    fn bit_writer_aligned_bytes_no_completion_tag() {
        let mut w = BitWriter::with_bit_capacity(24);
        w.push_bytes(&[0xAB, 0xCD, 0xEF]);
        assert_eq!(w.bit_len(), 24);
        let (out, len) = w.finalize_with_completion_tag();
        assert_eq!(len, 24);
        assert_eq!(out, vec![0xAB, 0xCD, 0xEF]);
    }

    /// A `1`-bit followed by a byte must end up at bit positions 0 and 1..9,
    /// so the two emitted bytes are `1<<7 | 0xAB>>1 = 0xD5` and
    /// `0xAB << 7 | completion 1-bit = 0x80 | 0x40 = 0xC0` (completion tag).
    #[test]
    fn bit_writer_unaligned_byte_split() {
        let mut w = BitWriter::with_bit_capacity(9);
        w.push_bit(true);
        w.push_byte(0xAB);
        assert_eq!(w.bit_len(), 9);
        let (out, len) = w.finalize_with_completion_tag();
        assert_eq!(len, 9);
        // Expected layout (MSB-first):
        //   bit 0:    1                    → byte 0 MSB
        //   bits 1-8: 10101011 (0xAB)      → byte 0 bits 1-7 + byte 1 bit 0
        //   bit 9:    1 (completion tag)   → byte 1 bit 1
        //   bits 10-15: 000000 (pad)       → byte 1 bits 2-7
        // byte 0 = 1_1010101 = 0xD5
        // byte 1 = 1_1_000000 = 0xC0
        assert_eq!(out, vec![0xD5, 0xC0]);
    }

    /// 322-bit payload (wallet v5r1) must produce exactly 41 bytes of
    /// bit-packed data + 1 tag byte = 41 bytes total (completion tag fits
    /// in the last partial byte). Regression test for the byte count.
    #[test]
    fn bit_writer_wallet_v5r1_length() {
        let mut w = BitWriter::with_bit_capacity(322);
        w.push_bit(true);
        w.push_u32_be(0);
        w.push_i32_be(-239);
        w.push_bytes(&[0u8; 32]);
        w.push_bit(false);
        let (out, len) = w.finalize_with_completion_tag();
        assert_eq!(len, 322);
        // ceil(322/8) = 41 (the completion tag fits within the final byte)
        assert_eq!(out.len(), 41);
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
