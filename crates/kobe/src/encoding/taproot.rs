//! BIP-341 key-path-only tweak shared by Bitcoin `P2TR` and OneKey-style
//! Kaspa addresses.

use alloc::string::String;
use alloc::vec::Vec;

use k256::elliptic_curve::ff::PrimeField as _;
use k256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest as _, Sha256};

use crate::Error;

/// `x(Q)` where `Q = lift_x(P) + t·G`, `t = hashTapTweak(x(P))` (empty merkle
/// root; BIP-341 fails when `t >= n`, which never occurs in practice).
pub(crate) fn tweaked_x(internal_x: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut even_key = Vec::with_capacity(33);
    even_key.push(0x02);
    even_key.extend_from_slice(internal_x);
    let internal = k256::PublicKey::from_sec1_bytes(&even_key)
        .map_err(|e| Error::InvalidKey(alloc::format!("taproot internal key: {e}")))?;

    let tag = Sha256::digest(b"TapTweak");
    let tweak_bytes: [u8; 32] = Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(internal_x)
        .finalize()
        .into();
    let tweak = Option::<k256::Scalar>::from(k256::Scalar::from_repr(tweak_bytes.into()))
        .ok_or_else(|| Error::InvalidKey(String::from("taproot tweak out of range")))?;

    let q = k256::ProjectivePoint::from(*internal.as_affine())
        + k256::ProjectivePoint::GENERATOR * tweak;
    let encoded = q.to_affine().to_sec1_point(true);
    let output_x = encoded
        .x()
        .ok_or_else(|| Error::InvalidKey(String::from("taproot output key at infinity")))?;

    let mut out = [0u8; 32];
    out.copy_from_slice(output_x);
    Ok(out)
}
