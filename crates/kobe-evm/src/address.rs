//! Ethereum address encoding (public data only — no private keys).

use alloc::string::String;

use sha3::{Digest, Keccak256};

/// EIP-55 mixed-case checksum encoding of a 20-byte address (`0x` prefixed).
///
/// The address is hex-encoded lowercase, the ASCII hex is hashed with
/// Keccak-256, and each hex letter is uppercased when the corresponding
/// nibble of the hash is `>= 8`. See
/// [EIP-55](https://eips.ethereum.org/EIPS/eip-55).
#[must_use]
pub fn to_checksum(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let hash = Keccak256::digest(lower.as_bytes());

    let (pairs, _) = lower.as_bytes().as_chunks::<2>();
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (pair, &h) in pairs.iter().zip(hash.iter()) {
        for (c, nibble) in pair.iter().zip([h >> 4, h & 0x0f]) {
            let c = char::from(*c);
            out.push(if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            });
        }
    }
    out
}

/// EIP-55 checksummed address of a 65-byte SEC1 uncompressed public key:
/// `keccak256(key[1..])[12..]`.
pub(crate) fn address_from_uncompressed(key: &[u8; 65]) -> String {
    let &[_, public_key @ ..] = key;
    let hash: [u8; 32] = Keccak256::digest(public_key).into();
    let [_, _, _, _, _, _, _, _, _, _, _, _, tail @ ..] = hash;
    to_checksum(&tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex_str: &str) -> [u8; 20] {
        let mut out = [0u8; 20];
        hex::decode_to_slice(hex_str.trim_start_matches("0x"), &mut out).unwrap();
        out
    }

    /// The four official EIP-55 test vectors.
    /// <https://eips.ethereum.org/EIPS/eip-55>
    #[test]
    fn eip55_spec_vectors() {
        for (input, expected) in [
            (
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ] {
            assert_eq!(to_checksum(&bytes(input)), expected);
        }
    }
}
