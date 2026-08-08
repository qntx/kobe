//! Wallet Import Format (compressed secp256k1).
//!
//! Secret material enters and leaves only as [`Zeroizing`].

use alloc::string::String;

use kobe_primitives::DeriveError;
use kobe_primitives::encoding::base58check_encode;
#[cfg(test)]
use kobe_primitives::encoding::double_sha256;
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
    let mut body = Zeroizing::new([0u8; 34]);
    body[0] = match network {
        Network::Mainnet => 0x80,
        Network::Testnet => 0xef,
    };
    body[1..33].copy_from_slice(private_key.as_ref());
    body[33] = 0x01;

    Ok(Zeroizing::new(base58check_encode(body.as_slice())))
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
        let checksum = double_sha256(&decoded[..34]);
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
