//! Bitcoin-family address formats: `P2PKH`, `P2SH-P2WPKH`, `P2WPKH`.

use alloc::string::String;

use crate::encoding::base58::base58check_versioned;
use crate::encoding::hash::hash160;

/// `P2PKH` address: `Base58Check(version ‖ hash160(pubkey))`.
pub(crate) fn p2pkh(version: u8, compressed_pubkey: &[u8; 33]) -> String {
    base58check_versioned(version, &hash160(compressed_pubkey))
}

/// `P2SH-P2WPKH` address: a segwit redeem script inside `P2SH`.
#[cfg(any(feature = "btc", feature = "ltc"))]
pub(crate) fn p2sh_p2wpkh(version: u8, compressed_pubkey: &[u8; 33]) -> String {
    let mut redeem = alloc::vec::Vec::with_capacity(22);
    redeem.push(0x00);
    redeem.push(0x14);
    redeem.extend_from_slice(&hash160(compressed_pubkey));
    base58check_versioned(version, &hash160(&redeem))
}

/// `P2WPKH` address: segwit-v0 bech32 over `hash160(pubkey)`.
#[cfg(any(feature = "btc", feature = "ltc"))]
pub(crate) fn p2wpkh(
    hrp: bech32::Hrp,
    compressed_pubkey: &[u8; 33],
) -> Result<String, crate::Error> {
    bech32::segwit::encode_v0(hrp, &hash160(compressed_pubkey))
        .map_err(|e| crate::Error::InvalidKey(alloc::format!("bech32: {e}")))
}
