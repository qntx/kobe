//! Minimal RLP codec for EVM transaction envelopes.
//!
//! Only the subset needed to validate an unsigned transaction and to append
//! `(v, r, s)` / `(yParity, r, s)` to its field list.

use alloc::vec;
use alloc::vec::Vec;

/// RLP-encode a byte string.
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "single-element check guards the index"
)]
pub(crate) fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = encode_length(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

/// RLP-encode a `u64` as a minimal-width RLP integer (`0` → `0x80`).
#[must_use]
pub(crate) fn encode_u64(val: u64) -> Vec<u8> {
    encode_bytes(strip_leading_zeros(&val.to_be_bytes()))
}

/// RLP-encode a `u128` as a minimal-width RLP integer (`0` → `0x80`).
///
/// Needed for legacy `v`, which can exceed `u64` for large chain ids
/// (`v = chain_id * 2 + 35 + parity`).
#[must_use]
pub(crate) fn encode_u128(val: u128) -> Vec<u8> {
    encode_bytes(strip_leading_zeros(&val.to_be_bytes()))
}

/// RLP-encode a list from already-encoded concatenated items.
#[must_use]
pub(crate) fn encode_list(items: &[u8]) -> Vec<u8> {
    let mut out = encode_length(items.len(), 0xc0);
    out.extend_from_slice(items);
    out
}

/// Strip leading zeros from a big-endian scalar.
#[must_use]
#[allow(
    clippy::indexing_slicing,
    reason = "start is bounded by data.len() via unwrap_or"
)]
pub(crate) fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[start..]
}

/// Decode `data` as a single RLP list spanning it exactly.
///
/// Returns the list's payload (the concatenation of its encoded items).
/// Errors on a non-list item or trailing bytes.
#[allow(
    clippy::indexing_slicing,
    reason = "item bounds are validated by decode_length before slicing"
)]
pub(crate) fn decode_list(data: &[u8]) -> Result<&[u8], &'static str> {
    let (offset, length) = decode_length(data)?;
    if data.first().copied().unwrap_or(0) < 0xc0 {
        return Err("expected an RLP list");
    }
    if data.len() < offset + length {
        return Err("truncated RLP payload");
    }
    if data.len() != offset + length {
        return Err("trailing bytes after RLP list");
    }
    Ok(&data[offset..])
}

/// Split an RLP list payload into its encoded items.
#[allow(
    clippy::indexing_slicing,
    reason = "item bounds are validated by decode_length before slicing"
)]
pub(crate) fn list_items(payload: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    let mut items = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let (offset, length) = decode_length(rest)?;
        if rest.len() < offset + length {
            return Err("truncated RLP item");
        }
        items.push(&rest[..offset + length]);
        rest = &rest[offset + length..];
    }
    Ok(items)
}

/// Decode one item and return its payload bytes (without the length prefix).
///
/// The item must be a byte string, not a nested list.
#[allow(
    clippy::indexing_slicing,
    reason = "item bounds are validated by decode_length before slicing"
)]
pub(crate) fn item_payload(item: &[u8]) -> Result<&[u8], &'static str> {
    if item.first().copied().unwrap_or(0) >= 0xc0 {
        return Err("expected an RLP byte string, got a list");
    }
    let (offset, length) = decode_length(item)?;
    if item.len() != offset + length {
        return Err("malformed RLP item");
    }
    Ok(&item[offset..])
}

/// `true` when the encoded item is the RLP empty string (`0x80`).
#[must_use]
pub(crate) fn is_rlp_zero(item: &[u8]) -> bool {
    item == [0x80]
}

/// Append `(yParity, r, s)` to an unsigned typed transaction.
///
/// Input:  `type_byte || RLP([…fields])` with `type_byte` `0x01`, `0x02` or
/// `0x04`.
/// Output: `type_byte || RLP([…fields, yParity, r, s])`
#[allow(
    clippy::indexing_slicing,
    reason = "bounds are checked before every slice operation"
)]
pub(crate) fn encode_signed_typed_tx(
    unsigned_tx: &[u8],
    y_parity: u8,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let Some((&type_byte, rest)) = unsigned_tx.split_first() else {
        return Err("empty transaction");
    };
    if !matches!(type_byte, 0x01 | 0x02 | 0x04) {
        return Err("unsupported transaction type (expected 0x01, 0x02 or 0x04)");
    }
    let items = decode_list(rest)?;

    let v_enc = encode_bytes(strip_leading_zeros(&[y_parity]));
    let r_enc = encode_bytes(strip_leading_zeros(r));
    let s_enc = encode_bytes(strip_leading_zeros(s));

    let mut new_items = items.to_vec();
    new_items.extend_from_slice(&v_enc);
    new_items.extend_from_slice(&r_enc);
    new_items.extend_from_slice(&s_enc);

    let mut result = vec![type_byte];
    result.extend_from_slice(&encode_list(&new_items));
    Ok(result)
}

/// Rebuild a signed legacy transaction from its 9-item unsigned form.
///
/// Input: the payload of `RLP([nonce, gasPrice, gasLimit, to, value, data,
/// chainId, 0, 0])` — already validated to hold exactly 9 items.
/// Output: `RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`.
pub(crate) fn encode_signed_legacy_tx(
    payload: &[u8],
    chain_id: u64,
    recovery: u8,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let items = list_items(payload)?;
    let Some(&[nonce, gas_price, gas_limit, to, value, data]) = items.first_chunk::<6>() else {
        return Err("legacy transaction requires 9 fields");
    };
    // `u64 * 2 + 36` fits in u128, so no checked arithmetic is needed.
    let v = u128::from(chain_id) * 2 + 35 + u128::from(recovery);

    let mut new_items = Vec::new();
    for item in [nonce, gas_price, gas_limit, to, value, data] {
        new_items.extend_from_slice(item);
    }
    new_items.extend_from_slice(&encode_u128(v));
    new_items.extend_from_slice(&encode_bytes(strip_leading_zeros(r)));
    new_items.extend_from_slice(&encode_bytes(strip_leading_zeros(s)));
    Ok(encode_list(&new_items))
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "guarded: len < 56 and len_bytes.len() <= 8"
)]
fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let len_bytes = be_bytes(len);
        let mut out = vec![offset + 55 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out
    }
}

#[allow(
    clippy::indexing_slicing,
    reason = "start is bounded by bytes.len() via position/unwrap_or"
)]
fn be_bytes(val: usize) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

#[allow(
    clippy::indexing_slicing,
    reason = "emptiness checked first; length validated before each slice"
)]
fn decode_length(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("empty input");
    }
    let prefix = data[0];
    match prefix {
        0x00..=0x7f => Ok((0, 1)),
        0x80..=0xb7 => Ok((1, usize::from(prefix - 0x80))),
        0xb8..=0xbf => {
            let n = usize::from(prefix - 0xb7);
            if data.len() < 1 + n {
                return Err("truncated length");
            }
            Ok((1 + n, read_be(&data[1..=n])))
        }
        0xc0..=0xf7 => Ok((1, usize::from(prefix - 0xc0))),
        0xf8..=0xff => {
            let n = usize::from(prefix - 0xf7);
            if data.len() < 1 + n {
                return Err("truncated length");
            }
            Ok((1 + n, read_be(&data[1..=n])))
        }
    }
}

fn read_be(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    reason = "test assertions use indexing for clarity"
)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn encode_single_byte() {
        assert_eq!(encode_bytes(&[0x42]), vec![0x42]);
    }

    #[test]
    fn encode_empty() {
        assert_eq!(encode_bytes(&[]), vec![0x80]);
        assert_eq!(encode_list(&[]), vec![0xc0]);
    }

    #[test]
    fn v_zero_is_rlp_integer_zero() {
        assert_eq!(encode_bytes(strip_leading_zeros(&[0])), vec![0x80]);
    }

    #[test]
    fn encode_u64_minimal_width() {
        assert_eq!(encode_u64(0), vec![0x80]);
        assert_eq!(encode_u64(1), vec![0x01]);
        assert_eq!(encode_u64(1024), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn decode_list_requires_exact_span() {
        let list = encode_list(&encode_bytes(&[1]));
        assert_eq!(decode_list(&list).unwrap(), encode_bytes(&[1]).as_slice());
        let mut padded = list;
        padded.push(0);
        assert!(decode_list(&padded).is_err());
        assert!(decode_list(&encode_bytes(&[1])).is_err());
    }

    #[test]
    fn list_items_splits_payload() {
        let items = [encode_bytes(&[1]), encode_list(&encode_bytes(&[2]))].concat();
        let parsed = list_items(&items).unwrap();
        assert_eq!(
            parsed,
            [encode_bytes(&[1]), encode_list(&encode_bytes(&[2]))]
        );
    }

    #[test]
    fn rejects_legacy_tx_in_typed_encoder() {
        assert!(encode_signed_typed_tx(&[0xc0], 0, &[0; 32], &[0; 32]).is_err());
        assert!(encode_signed_typed_tx(&[0x03, 0xc0], 0, &[0; 32], &[0; 32]).is_err());
    }

    #[test]
    fn roundtrip_eip1559() {
        let items: Vec<u8> = [
            encode_bytes(&[1]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_list(&[]),
        ]
        .concat();
        let mut unsigned = vec![0x02];
        unsigned.extend_from_slice(&encode_list(&items));

        let signed = encode_signed_typed_tx(&unsigned, 1, &[0; 32], &[0; 32]).unwrap();
        assert_eq!(signed[0], 0x02);
    }

    #[test]
    fn legacy_signed_list_keeps_first_six_items() {
        // rlp([nonce=0x18, gasPrice=0x01, gasLimit=0x5208, to=0x3535..(20B),
        //      value=0x01, data="", chainId=0xaa36a7, 0, 0]).
        let to = hex::decode("3535353535353535353535353535353535353535").unwrap();
        let payload: Vec<u8> = [
            encode_bytes(&[0x18]),
            encode_bytes(&[1]),
            encode_bytes(&[0x52, 0x08]),
            encode_bytes(&to),
            encode_bytes(&[1]),
            encode_bytes(&[]),
            encode_bytes(&[0xaa, 0x36, 0xa7]),
            encode_bytes(&[]),
            encode_bytes(&[]),
        ]
        .concat();
        // chainId 11155111 → v = 22310257 (0x1544991) + parity.
        let signed =
            encode_signed_legacy_tx(&payload, 11_155_111, 0, &[0xAA; 32], &[0xBB; 32]).unwrap();
        let signed_payload = decode_list(&signed).unwrap();
        let items = list_items(signed_payload).unwrap();
        assert_eq!(items.len(), 9);
        // v = 2 * 11155111 + 35 + 0 = 22310257 = 0x01546D71.
        assert_eq!(item_payload(items[6]).unwrap(), &[0x01, 0x54, 0x6D, 0x71]);
        assert_eq!(item_payload(items[7]).unwrap().len(), 32);
        assert_eq!(item_payload(items[8]).unwrap().len(), 32);
    }
}
