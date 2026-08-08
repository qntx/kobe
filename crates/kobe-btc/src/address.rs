//! Bitcoin address encoding (public data only — no private keys).

use alloc::format;
use alloc::string::String;

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, Scalar, U256};
use kobe_primitives::DeriveError;
use kobe_primitives::encoding::{base58check_versioned, hash160};
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

fn p2pkh(public_key: &[u8; 33], network: Network) -> String {
    let version = match network {
        Network::Mainnet => 0x00,
        Network::Testnet => 0x6f,
    };
    base58check_versioned(version, &hash160(public_key))
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
    base58check_versioned(version, &hash160(&redeem))
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
/// Internal key: BIP-340 x-only (`lift_x`, even-y).
/// Output key: `Q = P + t·G` with `t = int(hashTapTweak(x)) mod n`.
/// The address program is the x-coordinate of `Q` (parity is irrelevant for
/// encoding). This crate does not sign or spend.
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
    // BIP-341: t = int(hashTapTweak(...)) mod n (not reject-if-out-of-range).
    let tweak = <Scalar as Reduce<U256>>::reduce_bytes(&tweak_bytes.into());

    let q_proj = ProjectivePoint::from(*internal.as_affine()) + ProjectivePoint::GENERATOR * tweak;
    // Address program is the x-coordinate of Q. Negating Q preserves x, so
    // even-y normalization is not required for encoding (only for signing).
    let encoded = q_proj.to_affine().to_encoded_point(true);
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
