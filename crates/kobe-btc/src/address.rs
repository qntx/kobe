//! Bitcoin address encoding (public data only — no private keys).

use alloc::format;
use alloc::string::String;

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, Scalar};
use kobe_primitives::DeriveError;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::{AddressType, Network};

/// Build an address string from a compressed secp256k1 public key.
pub(crate) fn create_address(
    public_key: &[u8; 33],
    network: Network,
    address_type: AddressType,
) -> Result<String, DeriveError> {
    match public_key.first().copied() {
        Some(0x02 | 0x03) => {}
        _ => {
            return Err(DeriveError::Crypto(
                "btc: expected compressed public key prefix 0x02 or 0x03".into(),
            ));
        }
    }

    match address_type {
        AddressType::P2pkh => Ok(p2pkh(public_key, network)),
        AddressType::P2shP2wpkh => Ok(p2sh_p2wpkh(public_key, network)),
        AddressType::P2wpkh => p2wpkh(public_key, network),
        AddressType::P2tr => p2tr(public_key, network),
    }
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

#[allow(
    clippy::indexing_slicing,
    reason = "fixed-size Base58Check fields are checked by construction"
)]
fn base58check(version: u8, payload_20: &[u8; 20]) -> String {
    let mut buf = [0u8; 25];
    buf[0] = version;
    buf[1..21].copy_from_slice(payload_20);
    let first = Sha256::digest(&buf[..21]);
    let checksum = Sha256::digest(first);
    buf[21..].copy_from_slice(&checksum[..4]);
    bs58::encode(buf).into_string()
}

fn p2pkh(public_key: &[u8; 33], network: Network) -> String {
    let version = match network {
        Network::Mainnet => 0x00,
        Network::Testnet => 0x6f,
    };
    base58check(version, &hash160(public_key))
}

fn p2sh_p2wpkh(public_key: &[u8; 33], network: Network) -> String {
    let pubkey_hash = hash160(public_key);
    // P2WPKH redeem script: OP_0 PUSH_20 <hash160(pubkey)>
    let mut redeem = [0u8; 22];
    redeem[0] = 0x00;
    redeem[1] = 0x14;
    redeem[2..].copy_from_slice(&pubkey_hash);

    let version = match network {
        Network::Mainnet => 0x05,
        Network::Testnet => 0xc4,
    };
    base58check(version, &hash160(&redeem))
}

fn p2wpkh(public_key: &[u8; 33], network: Network) -> Result<String, DeriveError> {
    let program = hash160(public_key);
    let hrp = match network {
        Network::Mainnet => bech32::hrp::BC,
        Network::Testnet => bech32::hrp::TB,
    };
    bech32::segwit::encode_v0(hrp, &program)
        .map_err(|e| DeriveError::AddressEncoding(format!("btc p2wpkh: {e}")))
}

/// Key-path-only P2TR (BIP-341).
///
/// Internal key: BIP-340 x-only (even-y lift).
/// Output key: `Q = P + t·G`, then even-y normalized (`Q = -Q` if odd).
/// This crate only encodes addresses; it does not sign or spend.
fn p2tr(public_key: &[u8; 33], network: Network) -> Result<String, DeriveError> {
    let mut even_key = *public_key;
    even_key[0] = 0x02;
    let internal = PublicKey::from_sec1_bytes(&even_key)
        .map_err(|e| DeriveError::Crypto(format!("btc p2tr internal key: {e}")))?;
    let internal_x = &even_key[1..];

    let tag = Sha256::digest(b"TapTweak");
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    hasher.update(internal_x);
    let tweak_bytes: [u8; 32] = hasher.finalize().into();
    let tweak = Option::<Scalar>::from(Scalar::from_repr(tweak_bytes.into())).ok_or_else(|| {
        DeriveError::Crypto("btc p2tr: TapTweak not in secp256k1 scalar field".into())
    })?;

    let q_proj = ProjectivePoint::from(*internal.as_affine()) + ProjectivePoint::GENERATOR * tweak;
    let mut affine = q_proj.to_affine();
    let mut encoded = affine.to_encoded_point(true);
    // x-only output key must be the even-y representative.
    if encoded.as_bytes().first().copied() == Some(0x03) {
        affine = (-ProjectivePoint::from(affine)).to_affine();
        encoded = affine.to_encoded_point(true);
    }
    let output_x = encoded
        .x()
        .ok_or_else(|| DeriveError::Crypto("btc p2tr: output key at infinity".into()))?;

    let hrp = match network {
        Network::Mainnet => bech32::hrp::BC,
        Network::Testnet => bech32::hrp::TB,
    };
    bech32::segwit::encode_v1(hrp, output_x)
        .map_err(|e| DeriveError::AddressEncoding(format!("btc p2tr: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> [u8; 33] {
        let mut pk = [0u8; 33];
        hex::decode_to_slice(
            "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
            &mut pk,
        )
        .unwrap();
        pk
    }

    #[test]
    fn rejects_uncompressed_prefix() {
        let mut pk = test_pubkey();
        pk[0] = 0x04;
        assert!(matches!(
            create_address(&pk, Network::Mainnet, AddressType::P2wpkh),
            Err(DeriveError::Crypto(_))
        ));
    }

    #[test]
    fn p2wpkh_mainnet_prefix() {
        let a = create_address(&test_pubkey(), Network::Mainnet, AddressType::P2wpkh).unwrap();
        assert!(a.starts_with("bc1q"));
    }

    #[test]
    fn p2wpkh_testnet_prefix() {
        let a = create_address(&test_pubkey(), Network::Testnet, AddressType::P2wpkh).unwrap();
        assert!(a.starts_with("tb1q"));
    }

    #[test]
    fn p2pkh_mainnet_prefix() {
        let a = create_address(&test_pubkey(), Network::Mainnet, AddressType::P2pkh).unwrap();
        assert!(a.starts_with('1'));
    }

    #[test]
    fn p2pkh_testnet_prefix() {
        let a = create_address(&test_pubkey(), Network::Testnet, AddressType::P2pkh).unwrap();
        assert!(matches!(a.chars().next(), Some('m' | 'n')));
    }

    #[test]
    fn p2sh_mainnet_prefix() {
        let a = create_address(&test_pubkey(), Network::Mainnet, AddressType::P2shP2wpkh).unwrap();
        assert!(a.starts_with('3'));
    }

    #[test]
    fn p2sh_testnet_prefix() {
        let a = create_address(&test_pubkey(), Network::Testnet, AddressType::P2shP2wpkh).unwrap();
        assert!(a.starts_with('2'));
    }

    #[test]
    fn p2tr_mainnet_prefix() {
        let a = create_address(&test_pubkey(), Network::Mainnet, AddressType::P2tr).unwrap();
        assert!(a.starts_with("bc1p"));
    }

    #[test]
    fn p2tr_testnet_prefix() {
        let a = create_address(&test_pubkey(), Network::Testnet, AddressType::P2tr).unwrap();
        assert!(a.starts_with("tb1p"));
    }
}
