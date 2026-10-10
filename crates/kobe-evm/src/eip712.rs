//! EIP-712 typed structured data hashing (v4).

#[cfg(not(feature = "std"))]
use alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use sha3::{Digest, Keccak256};

use crate::Error;

/// Compute the EIP-712 hash from a JSON string.
///
/// Returns the 32-byte digest: `keccak256("\x19\x01" || domainSeparator || structHash)`.
///
/// # Errors
///
/// Returns [`Error::Input`] on malformed JSON or invalid typed data.
pub(crate) fn hash_typed_data_json(json: &str) -> Result<[u8; 32], Error> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| Error::Input(e.to_string()))?;

    let types_val = v
        .get("types")
        .ok_or_else(|| Error::Input("missing 'types'".into()))?;
    let primary_type = v
        .get("primaryType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Input("missing 'primaryType'".into()))?;
    let domain = v
        .get("domain")
        .ok_or_else(|| Error::Input("missing 'domain'".into()))?;
    let message = v
        .get("message")
        .ok_or_else(|| Error::Input("missing 'message'".into()))?;

    let types = parse_types(types_val)?;

    let domain_hash = hash_struct("EIP712Domain", domain, &types)?;
    let message_hash = hash_struct(primary_type, message, &types)?;

    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_hash);
    buf.extend_from_slice(&message_hash);
    Ok(Keccak256::digest(&buf).into())
}

type TypeDefs = BTreeMap<String, Vec<(String, String)>>; // name → [(field_name, field_type)]

fn parse_types(val: &serde_json::Value) -> Result<TypeDefs, Error> {
    let obj = val
        .as_object()
        .ok_or_else(|| Error::Input("'types' must be object".into()))?;
    let mut types = BTreeMap::new();
    for (name, fields) in obj {
        let arr = fields
            .as_array()
            .ok_or_else(|| Error::Input(format!("{name}: expected array")))?;
        let mut parsed = Vec::new();
        for f in arr {
            let n = f
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Input("field missing 'name'".into()))?;
            let t = f
                .get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Input("field missing 'type'".into()))?;
            parsed.push((n.to_owned(), t.to_owned()));
        }
        types.insert(name.clone(), parsed);
    }
    Ok(types)
}

fn hash_struct(
    type_name: &str,
    data: &serde_json::Value,
    types: &TypeDefs,
) -> Result<[u8; 32], Error> {
    let th = type_hash(type_name, types)?;
    let encoded = encode_data(type_name, data, types)?;
    let mut buf = Vec::with_capacity(32 + encoded.len());
    buf.extend_from_slice(&th);
    buf.extend_from_slice(&encoded);
    Ok(Keccak256::digest(&buf).into())
}

fn type_hash(type_name: &str, types: &TypeDefs) -> Result<[u8; 32], Error> {
    let s = encode_type(type_name, types)?;
    Ok(Keccak256::digest(s.as_bytes()).into())
}

fn encode_type(type_name: &str, types: &TypeDefs) -> Result<String, Error> {
    let fields = types
        .get(type_name)
        .ok_or_else(|| Error::Input(format!("unknown type: {type_name}")))?;
    let mut deps = BTreeSet::new();
    collect_deps(type_name, types, &mut deps);
    deps.remove(type_name);

    let mut result = format_struct(type_name, fields);
    for dep in &deps {
        if let Some(f) = types.get(dep.as_str()) {
            result.push_str(&format_struct(dep, f));
        }
    }
    Ok(result)
}

fn format_struct(name: &str, fields: &[(String, String)]) -> String {
    let params: Vec<String> = fields.iter().map(|(n, t)| format!("{t} {n}")).collect();
    format!("{name}({})", params.join(","))
}

fn collect_deps(type_name: &str, types: &TypeDefs, out: &mut BTreeSet<String>) {
    if let Some(fields) = types.get(type_name) {
        for (_, t) in fields {
            let base = base_type(t);
            if types.contains_key(base) && !out.contains(base) {
                out.insert(base.to_owned());
                collect_deps(base, types, out);
            }
        }
    }
}

fn base_type(t: &str) -> &str {
    t.find('[').map_or(t, |i| &t[..i])
}

fn encode_data(
    type_name: &str,
    data: &serde_json::Value,
    types: &TypeDefs,
) -> Result<Vec<u8>, Error> {
    let fields = types
        .get(type_name)
        .ok_or_else(|| Error::Input(format!("unknown type: {type_name}")))?;
    let obj = data
        .as_object()
        .ok_or_else(|| Error::Input(format!("expected object for {type_name}")))?;

    let mut out = Vec::new();
    for (name, type_str) in fields {
        let val = obj.get(name).unwrap_or(&serde_json::Value::Null);
        out.extend_from_slice(&encode_value(type_str, val, types)?);
    }
    Ok(out)
}

fn encode_value(
    type_name: &str,
    value: &serde_json::Value,
    types: &TypeDefs,
) -> Result<[u8; 32], Error> {
    if type_name.ends_with(']') {
        let base = base_type(type_name);
        let arr = value
            .as_array()
            .ok_or_else(|| Error::Input(format!("expected array for {type_name}")))?;
        let mut inner = Vec::new();
        for item in arr {
            inner.extend_from_slice(&encode_value(base, item, types)?);
        }
        return Ok(Keccak256::digest(&inner).into());
    }
    if types.contains_key(type_name) {
        return hash_struct(type_name, value, types);
    }
    encode_atomic(type_name, value)
}

#[allow(
    clippy::many_single_char_names,
    reason = "EIP-712 spec uses short names: w, b, n, t, s"
)]
#[allow(
    clippy::indexing_slicing,
    reason = "all slices are bounded by prior validation or fixed-size outputs"
)]
fn encode_atomic(ty: &str, value: &serde_json::Value) -> Result<[u8; 32], Error> {
    let mut w = [0u8; 32];
    match ty {
        "address" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::Input("address must be string".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let b = hex::decode(s).map_err(|e| Error::Input(format!("bad address: {e}")))?;
            if b.len() != 20 {
                return Err(Error::Input(format!(
                    "address: expected 20 bytes, got {}",
                    b.len()
                )));
            }
            w[12..].copy_from_slice(&b);
            Ok(w)
        }
        "bool" => {
            if value.as_bool().unwrap_or(false) {
                w[31] = 1;
            }
            Ok(w)
        }
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::Input("string must be string".into()))?;
            Ok(Keccak256::digest(s.as_bytes()).into())
        }
        "bytes" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::Input("bytes must be hex string".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let b = hex::decode(s).map_err(|e| Error::Input(format!("bad bytes: {e}")))?;
            Ok(Keccak256::digest(&b).into())
        }
        t if t.starts_with("bytes") => {
            let n: usize = t[5..]
                .parse()
                .map_err(|_| Error::Input(format!("invalid type: {t}")))?;
            if !(1..=32).contains(&n) {
                return Err(Error::Input("bytesN: N must be 1..32".to_owned()));
            }
            let s = value
                .as_str()
                .ok_or_else(|| Error::Input(format!("{t} must be hex string")))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let b = hex::decode(s).map_err(|e| Error::Input(format!("bad {t}: {e}")))?;
            if b.len() != n {
                return Err(Error::Input(format!(
                    "{t}: expected {n} bytes, got {}",
                    b.len()
                )));
            }
            w[..n].copy_from_slice(&b);
            Ok(w)
        }
        t if t.starts_with("uint") => encode_uint(t, &t[4..], value),
        t if t.starts_with("int") => encode_int(t, &t[3..], value),
        _ => Err(Error::Input(format!("unsupported EIP-712 type: {ty}"))),
    }
}

/// Parse an EIP-712 `uintN` value into a left-padded 256-bit big-endian word.
///
/// Enforces that the provided scalar fits in `N` bits.
#[allow(
    clippy::indexing_slicing,
    reason = "slices are bounded by prior length / capacity validation"
)]
fn encode_uint(ty: &str, bits_str: &str, value: &serde_json::Value) -> Result<[u8; 32], Error> {
    let bits = parse_int_width(ty, bits_str)?;
    let bytes_be = parse_uint_big_endian(value)?;

    // Strip superfluous leading zeros (hex input may be wider than `bits`).
    let first_nonzero = bytes_be
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes_be.len());
    let magnitude = &bytes_be[first_nonzero..];
    let byte_width = bits / 8;

    if magnitude.len() > byte_width {
        return Err(Error::Input(format!(
            "{ty}: value exceeds {bits}-bit range"
        )));
    }

    let mut w = [0u8; 32];
    w[32 - magnitude.len()..].copy_from_slice(magnitude);
    Ok(w)
}

/// Parse an EIP-712 `intN` value into a 256-bit two's-complement word.
fn encode_int(ty: &str, bits_str: &str, value: &serde_json::Value) -> Result<[u8; 32], Error> {
    let bits = parse_int_width(ty, bits_str)?;
    let (negative, magnitude) = parse_int_magnitude(value)?;

    check_int_range(ty, bits, negative, &magnitude)?;

    let mut w = [0u8; 32];
    write_be(&mut w, &magnitude);
    if negative {
        negate_twos_complement(&mut w);
    }
    Ok(w)
}

/// Range-check the magnitude of a signed integer against its declared width.
///
/// For an `intN` the valid range is `[-2^(N-1), 2^(N-1) - 1]`, i.e.:
///
/// - Positive (including zero): `magnitude < 2^(N-1)`.
/// - Negative: `magnitude <= 2^(N-1)`.
///
/// Implemented by composing `2^(N-1)` into a 33-byte big-endian buffer and
/// comparing it lexicographically against the caller's magnitude (also padded
/// to 33 bytes). The 33rd byte gives us one byte of headroom so the method
/// also correctly rejects anything wider than `int256`.
#[allow(
    clippy::indexing_slicing,
    reason = "threshold index is bounded by `bits <= 256` checked in `parse_int_width`"
)]
fn check_int_range(ty: &str, bits: usize, negative: bool, magnitude: &[u8]) -> Result<(), Error> {
    const BUF_LEN: usize = 33;

    if magnitude.len() > BUF_LEN {
        return Err(Error::Input(format!(
            "{ty}: value exceeds {bits}-bit signed range"
        )));
    }

    // Right-align magnitude into the 33-byte buffer.
    let mut mag = [0u8; BUF_LEN];
    mag[BUF_LEN - magnitude.len()..].copy_from_slice(magnitude);

    // Compose `2^(bits-1)` into the same buffer.
    let mut threshold = [0u8; BUF_LEN];
    let hi_bit = bits - 1;
    let byte_from_right = hi_bit / 8;
    let bit_in_byte = hi_bit % 8;
    threshold[BUF_LEN - 1 - byte_from_right] = 1u8 << bit_in_byte;

    let ord = mag.cmp(&threshold);
    let fits = matches!(
        (negative, ord),
        (false, core::cmp::Ordering::Less)
            | (true, core::cmp::Ordering::Less | core::cmp::Ordering::Equal),
    );
    if fits {
        return Ok(());
    }
    Err(Error::Input(format!(
        "{ty}: value exceeds {bits}-bit signed range"
    )))
}

fn parse_int_width(ty: &str, bits_str: &str) -> Result<usize, Error> {
    let bits: usize = bits_str
        .parse()
        .map_err(|_| Error::Input(format!("invalid type: {ty}")))?;
    // `u32::is_multiple_of` is not usable under MSRV without unstable.
    #[allow(clippy::manual_is_multiple_of, reason = "MSRV compatibility")]
    let not_byte_aligned = bits % 8 != 0;
    if bits == 0 || bits > 256 || not_byte_aligned {
        return Err(Error::Input(format!("{ty}: bad integer width {bits}")));
    }
    Ok(bits)
}

/// Parse a non-negative integer from a JSON value into big-endian bytes.
fn parse_uint_big_endian(value: &serde_json::Value) -> Result<Vec<u8>, Error> {
    if let Some(n) = value.as_u64() {
        return Ok(n.to_be_bytes().to_vec());
    }
    if let Some(s) = value.as_str() {
        if let Some(h) = s.strip_prefix("0x") {
            return hex::decode(h).map_err(|e| Error::Input(format!("bad uint hex: {e}")));
        }
        return parse_decimal_big_endian(s);
    }
    Err(Error::Input("uint must be number or string".into()))
}

/// Parse a signed integer into `(is_negative, magnitude_be_bytes)`, supporting
/// the full `int256` range (hex, positive, and negative decimal).
fn parse_int_magnitude(value: &serde_json::Value) -> Result<(bool, Vec<u8>), Error> {
    if let Some(n) = value.as_i64() {
        let unsigned = n.unsigned_abs();
        return Ok((n.is_negative(), unsigned.to_be_bytes().to_vec()));
    }
    if let Some(s) = value.as_str() {
        if let Some(h) = s.strip_prefix("0x") {
            // Hex encodes the magnitude; sign lives in a leading `-` if any.
            let bytes = hex::decode(h).map_err(|e| Error::Input(format!("bad int hex: {e}")))?;
            return Ok((false, bytes));
        }
        if let Some(rest) = s.strip_prefix('-') {
            let bytes = parse_decimal_big_endian(rest)?;
            return Ok((true, bytes));
        }
        if let Some(rest) = s.strip_prefix('+') {
            return Ok((false, parse_decimal_big_endian(rest)?));
        }
        return Ok((false, parse_decimal_big_endian(s)?));
    }
    Err(Error::Input("int must be number or string".into()))
}

/// Convert a decimal digit string into a minimal big-endian byte vector,
/// supporting integers wider than `u128` (essential for EIP-712 `int256` /
/// `uint256`).
fn parse_decimal_big_endian(s: &str) -> Result<Vec<u8>, Error> {
    if s.is_empty() {
        return Err(Error::Input("empty integer literal".into()));
    }
    if !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(Error::Input(format!("invalid integer literal: {s}")));
    }
    // Little-endian magnitude accumulator.
    let mut limbs: Vec<u8> = vec![0];
    for digit in s.bytes().map(|c| c - b'0') {
        let mut carry = u16::from(digit);
        for limb in &mut limbs {
            let v = u16::from(*limb) * 10 + carry;
            #[allow(
                clippy::cast_possible_truncation,
                reason = "low 8 bits by construction"
            )]
            {
                *limb = v as u8;
            }
            carry = v >> 8;
        }
        while carry != 0 {
            #[allow(clippy::cast_possible_truncation, reason = "pushed after shift by 8")]
            {
                limbs.push(carry as u8);
            }
            carry >>= 8;
        }
    }
    limbs.reverse();
    // Strip leading zeros but keep at least one byte.
    let first_nonzero = limbs
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(limbs.len() - 1);
    Ok(limbs.get(first_nonzero..).unwrap_or(&[]).to_vec())
}

/// Right-align a big-endian magnitude into a 32-byte word.
#[allow(
    clippy::indexing_slicing,
    reason = "magnitude length is checked against the 32-byte buffer before slicing"
)]
fn write_be(word: &mut [u8; 32], magnitude: &[u8]) {
    let start = 32_usize.saturating_sub(magnitude.len());
    // If `magnitude.len() > 32` the caller's range check must have already
    // rejected the value; truncate defensively to avoid UB.
    let src = if magnitude.len() > 32 {
        &magnitude[magnitude.len() - 32..]
    } else {
        magnitude
    };
    word[start..].copy_from_slice(src);
}

fn negate_twos_complement(bytes: &mut [u8; 32]) {
    for b in bytes.iter_mut() {
        *b = !*b;
    }
    let mut carry = 1u16;
    for b in bytes.iter_mut().rev() {
        let sum = u16::from(*b) + carry;
        #[allow(clippy::cast_possible_truncation, reason = "low byte by construction")]
        {
            *b = (sum & 0xFF) as u8;
        }
        carry = sum >> 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EIP712_EXAMPLE: &str = r#"{
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    }"#;

    #[test]
    fn full_eip712_hash() {
        let hash = hash_typed_data_json(EIP712_EXAMPLE).unwrap();
        assert_eq!(
            hex::encode(hash),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(hash_typed_data_json("not json").is_err());
    }

    #[test]
    fn uint_fits_within_declared_bits() {
        // uint8 = 255 fits; 256 must be rejected.
        let u8_max = encode_uint("uint8", "8", &serde_json::json!(255)).unwrap();
        assert_eq!(u8_max[31], 255);
        assert!(encode_uint("uint8", "8", &serde_json::json!(256)).is_err());

        // uint16 = 65_535 fits; 65_536 must be rejected.
        let u16_max = encode_uint("uint16", "16", &serde_json::json!(65_535)).unwrap();
        assert_eq!(u16_max[30], 0xFF);
        assert_eq!(u16_max[31], 0xFF);
        assert!(encode_uint("uint16", "16", &serde_json::json!(65_536)).is_err());
    }

    #[test]
    fn uint256_full_precision_decimal() {
        // 2^256 - 1
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        let out = encode_uint("uint256", "256", &serde_json::json!(max)).unwrap();
        assert!(out.iter().all(|&b| b == 0xFF));

        // 2^256 must be rejected.
        let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
        assert!(encode_uint("uint256", "256", &serde_json::json!(over)).is_err());
    }

    #[test]
    fn int_enforces_two_complement_range() {
        // int8 valid boundaries: -128..=127
        let pos_max = encode_int("int8", "8", &serde_json::json!(127)).unwrap();
        assert_eq!(pos_max[31], 127);
        let neg_min = encode_int("int8", "8", &serde_json::json!(-128)).unwrap();
        assert!(neg_min[..31].iter().all(|&b| b == 0xFF));
        assert_eq!(neg_min[31], 0x80);

        assert!(encode_int("int8", "8", &serde_json::json!(128)).is_err());
        assert!(encode_int("int8", "8", &serde_json::json!(-129)).is_err());
    }

    #[test]
    fn int256_full_precision_negative_decimal() {
        // -2^255 (minimum int256) must round-trip.
        let min = "-57896044618658097711785492504343953926634992332820282019728792003956564819968";
        let word = encode_int("int256", "256", &serde_json::json!(min)).unwrap();
        // Two's complement of 2^255 is 0x80 || zeros.
        assert_eq!(word[0], 0x80);
        assert!(word[1..].iter().all(|&b| b == 0));

        // -(2^255 + 1) must overflow.
        let under =
            "-57896044618658097711785492504343953926634992332820282019728792003956564819969";
        assert!(encode_int("int256", "256", &serde_json::json!(under)).is_err());
    }
}
