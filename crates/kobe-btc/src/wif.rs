//! Wallet Import Format (compressed secp256k1).
//!
//! Secret material enters and leaves only as [`Zeroizing`].

use alloc::string::String;

use kobe_primitives::DeriveError;
use sha2::{Digest, Sha256};
#[cfg(test)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::Network;

/// Encode a compressed private key as WIF.
///
/// This is infallible for any 32-byte key. It still returns [`Result`] so the
/// WIF path shares the same [`DeriveError`] surface as address encoding and
/// `derive_*` methods.
#[allow(
    clippy::indexing_slicing,
    reason = "fixed-size WIF payload fields are checked by construction"
)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "unified DeriveError surface with create_address / derive_*"
)]
pub(crate) fn encode_wif(
    private_key: &Zeroizing<[u8; 32]>,
    network: Network,
) -> Result<Zeroizing<String>, DeriveError> {
    let mut payload = Zeroizing::new([0u8; 38]);
    payload[0] = match network {
        Network::Mainnet => 0x80,
        Network::Testnet => 0xef,
    };
    payload[1..33].copy_from_slice(private_key.as_ref());
    payload[33] = 0x01;

    let first = Sha256::digest(&payload[..34]);
    let checksum = Sha256::digest(first);
    payload[34..].copy_from_slice(&checksum[..4]);

    Ok(Zeroizing::new(
        bs58::encode(payload.as_slice()).into_string(),
    ))
}

/// Decode compressed WIF (tests / round-trip only).
#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "decoded WIF length is validated before fixed field access"
)]
pub(crate) fn decode_wif(wif: &str) -> Result<(Zeroizing<[u8; 32]>, Network), DeriveError> {
    let mut decoded = bs58::decode(wif)
        .into_vec()
        .map_err(|_| DeriveError::Input("btc: invalid WIF base58".into()))?;

    let result = (|| {
        if decoded.len() != 38 {
            return Err(DeriveError::Input(
                "btc: invalid compressed WIF length".into(),
            ));
        }
        if decoded[33] != 0x01 {
            return Err(DeriveError::Input(
                "btc: WIF missing compressed flag".into(),
            ));
        }
        let first = Sha256::digest(&decoded[..34]);
        let checksum = Sha256::digest(first);
        if decoded[34..] != checksum[..4] {
            return Err(DeriveError::Input("btc: invalid WIF checksum".into()));
        }
        let network = match decoded[0] {
            0x80 => Network::Mainnet,
            0xef => Network::Testnet,
            _ => return Err(DeriveError::Input("btc: invalid WIF version".into())),
        };
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&decoded[1..33]);
        Ok((key, network))
    })();

    decoded.zeroize();
    result
}
