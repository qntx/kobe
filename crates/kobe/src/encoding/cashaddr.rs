//! `CashAddr`/`kaspa`-style encoding: `prefix:[version‖data ‖ checksum]`
//! with the shared cashaddr polymod checksum.

use alloc::string::String;
use alloc::vec::Vec;

/// The cashaddr character set.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// Shared cashaddr/kaspa polymod generators.
const GENERATORS: [u64; 5] = [
    0x0098_f2bc_8e61,
    0x0079_b76d_99e2,
    0x00f3_3e5f_b3c4,
    0x00ae_2eab_e2a8,
    0x001e_4f43_e470,
];

/// Encode `version ‖ data` under `prefix` as `prefix:qp…`.
///
/// `version` is one byte: for Bitcoin Cash it packs the address type and
/// the payload size; for Kaspa it is the script type (`0` = schnorr
/// pubkey).
pub(crate) fn encode(prefix: &str, version: u8, data: &[u8]) -> String {
    let mut payload = Vec::with_capacity(data.len() + 1);
    payload.push(version);
    payload.extend_from_slice(data);
    let values = convert_bits_8_to_5(&payload);

    let mut checksum_input = prefix_expand(prefix);
    checksum_input.extend_from_slice(&values);
    checksum_input.extend_from_slice(&[0; 8]);
    let checksum = polymod(checksum_input.iter().copied());

    let mut out = String::with_capacity(prefix.len() + 1 + values.len() + 8);
    out.push_str(prefix);
    out.push(':');
    for v in values {
        out.push(digit(v));
    }
    for i in (0..8).rev() {
        #[allow(clippy::cast_possible_truncation, reason = "masked to 5 bits")]
        let v = ((checksum >> (i * 5)) & 0x1f) as u8;
        out.push(digit(v));
    }
    out
}

fn digit(value: u8) -> char {
    char::from(*CHARSET.get(usize::from(value)).unwrap_or(&b'?'))
}

fn polymod(values: impl Iterator<Item = u8>) -> u64 {
    let mut c: u64 = 1;
    for d in values {
        let c0 = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) | u64::from(d);
        for &g in GENERATORS
            .iter()
            .enumerate()
            .filter(|(i, _)| (c0 >> i) & 1 != 0)
            .map(|(_, g)| g)
        {
            c ^= g;
        }
    }
    c ^ 1
}

fn prefix_expand(prefix: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + 1);
    out.extend(prefix.bytes().map(|b| b & 0x1f));
    out.push(0);
    out
}

fn convert_bits_8_to_5(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            #[allow(clippy::cast_possible_truncation, reason = "masked to 5 bits")]
            out.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        #[allow(clippy::cast_possible_truncation, reason = "masked to 5 bits")]
        out.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::encode;

    const CASHADDR: &str = include_str!("../../../../vectors/cashaddr.json");
    const KASPA_ADDRESS: &str = include_str!("../../../../vectors/kaspa-address.json");

    fn check_all(cases: &Value, payload_field: &str) {
        for case in cases.get("cases").and_then(Value::as_array).unwrap() {
            let payload =
                hex::decode(case.get(payload_field).and_then(Value::as_str).unwrap()).unwrap();
            let version =
                u8::try_from(case.get("version").and_then(Value::as_u64).unwrap()).unwrap();
            assert_eq!(
                encode(
                    case.get("prefix").and_then(Value::as_str).unwrap(),
                    version,
                    &payload
                ),
                case.get("address").and_then(Value::as_str).unwrap(),
                "{payload_field} {payload:?}"
            );
        }
    }

    /// Official cashaddr spec vectors: every payload size.
    #[test]
    fn cashaddr_spec_vectors() {
        check_all(&serde_json::from_str(CASHADDR).unwrap(), "payload");
    }

    /// Official rusty-kaspa address vectors (mainnet + testnet).
    #[test]
    fn kaspa_address_vectors() {
        check_all(&serde_json::from_str(KASPA_ADDRESS).unwrap(), "public_key");
    }
}
