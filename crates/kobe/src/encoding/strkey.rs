//! Stellar `StrKey`: `base32(version ‖ payload ‖ crc16-xmodem-le)`,
//! no padding. Version bytes `6 << 3` (account `G…`), `18 << 3`
//! (secret seed `S…`).

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

/// The `StrKey` version byte for an ed25519 public key (`G…`).
pub(crate) const VERSION_PUBLIC: u8 = 6 << 3;
/// The `StrKey` version byte for an ed25519 secret seed (`S…`).
pub(crate) const VERSION_SECRET: u8 = 18 << 3;

/// `version ‖ payload ‖ crc16` then base32-no-pad, into a zeroized string.
pub(crate) fn encode_secret(version: u8, payload: &[u8; 32]) -> Zeroizing<String> {
    let mut body = Zeroizing::new(Vec::with_capacity(35));
    body.push(version);
    body.extend_from_slice(payload);
    let crc = checksum(&body);
    body.extend_from_slice(&crc.to_le_bytes());
    let mut out = Zeroizing::new(String::with_capacity(56));
    data_encoding::BASE32_NOPAD.encode_append(&body, &mut out);
    out
}

/// `version ‖ payload ‖ crc16` then base32-no-pad (public material).
pub(crate) fn encode_public(version: u8, payload: &[u8; 32]) -> String {
    let mut body = Vec::with_capacity(35);
    body.push(version);
    body.extend_from_slice(payload);
    let crc = checksum(&body);
    body.extend_from_slice(&crc.to_le_bytes());
    data_encoding::BASE32_NOPAD.encode(&body)
}

const fn checksum(body: &[u8]) -> u16 {
    crc::Crc::<u16>::new(&crc::CRC_16_XMODEM).checksum(body)
}
