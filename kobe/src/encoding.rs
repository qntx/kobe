//! Encoding utilities for cryptocurrency addresses and keys.

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::hash::double_sha256;

/// Encode bytes to Base58Check (used in Bitcoin)
#[cfg(feature = "alloc")]
pub fn base58check_encode(version: &[u8], payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(version.len() + payload.len() + 4);
    data.extend_from_slice(version);
    data.extend_from_slice(payload);

    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);

    bs58::encode(data).into_string()
}

/// Decode Base58Check encoded string
#[cfg(feature = "alloc")]
pub fn base58check_decode(encoded: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let data = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| Error::InvalidEncoding)?;

    if data.len() < 5 {
        return Err(Error::InvalidLength {
            expected: 5,
            actual: data.len(),
        });
    }

    let (payload, checksum) = data.split_at(data.len() - 4);
    let computed_checksum = double_sha256(payload);

    if checksum != &computed_checksum[..4] {
        return Err(Error::InvalidChecksum);
    }

    // Assume first byte is version for Bitcoin-style addresses
    Ok((payload[..1].to_vec(), payload[1..].to_vec()))
}

/// Encode using Bech32/Bech32m for Bitcoin SegWit addresses.
///
/// Uses Bech32 for witness version 0, Bech32m for version 1+ (Taproot).
#[cfg(feature = "alloc")]
pub fn bech32_encode(hrp: &str, version: u8, data: &[u8]) -> Result<String> {
    use bech32::Hrp;

    let hrp = Hrp::parse(hrp).map_err(|_| Error::InvalidEncoding)?;
    let witness_version = bech32::Fe32::try_from(version).map_err(|_| Error::InvalidEncoding)?;

    bech32::segwit::encode(hrp, witness_version, data).map_err(|_| Error::InvalidEncoding)
}

/// Decode Bech32/Bech32m encoded SegWit address.
///
/// Returns (hrp, witness_version, witness_program).
#[cfg(feature = "alloc")]
pub fn bech32_decode(encoded: &str) -> Result<(String, u8, Vec<u8>)> {
    let (hrp, version, program) =
        bech32::segwit::decode(encoded).map_err(|_| Error::InvalidEncoding)?;

    Ok((hrp.to_string(), version.to_u8(), program))
}

/// Computes EIP-55 checksum encoding for an Ethereum address.
///
/// Returns a checksummed address string with mixed-case hex characters.
#[cfg(feature = "alloc")]
pub fn eip55_checksum(address: &[u8; 20]) -> String {
    let hex_addr = hex::encode(address);
    let hash = crate::hash::keccak256(hex_addr.as_bytes());

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            let hash_nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };

            if hash_nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c.to_ascii_lowercase());
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    mod base58check_tests {
        use super::*;

        #[test]
        fn test_base58check_encode_p2pkh_mainnet() {
            // Bitcoin P2PKH mainnet address (version 0x00)
            let version = hex_literal::hex!("00");
            let payload = hex_literal::hex!("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
            let encoded = base58check_encode(&version, &payload);
            assert_eq!(encoded, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        }

        #[test]
        fn test_base58check_encode_p2pkh_testnet() {
            // Bitcoin P2PKH testnet address (version 0x6f)
            let version = hex_literal::hex!("6f");
            let payload = hex_literal::hex!("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
            let encoded = base58check_encode(&version, &payload);
            assert_eq!(encoded, "mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt");
        }

        #[test]
        fn test_base58check_encode_p2sh_mainnet() {
            // Bitcoin P2SH mainnet address (version 0x05)
            let version = hex_literal::hex!("05");
            let payload = hex_literal::hex!("89abcdefabbaabbaabbaabbaabbaabbaabbaabba");
            let encoded = base58check_encode(&version, &payload);
            assert_eq!(encoded, "3EExK1K1TF3v7zsFtQHt14XqexCwgmXM1y");
        }

        #[test]
        fn test_base58check_encode_wif_uncompressed() {
            // WIF uncompressed private key (version 0x80)
            let version = hex_literal::hex!("80");
            let payload = hex_literal::hex!(
                "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
            );
            let encoded = base58check_encode(&version, &payload);
            assert_eq!(
                encoded,
                "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
            );
        }

        #[test]
        fn test_base58check_encode_wif_compressed() {
            // WIF compressed private key (version 0x80, payload ends with 0x01)
            let version = hex_literal::hex!("80");
            let payload = hex_literal::hex!(
                "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d01"
            );
            let encoded = base58check_encode(&version, &payload);
            assert_eq!(
                encoded,
                "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
            );
        }

        #[test]
        fn test_base58check_decode_p2pkh_mainnet() {
            let (version, payload) =
                base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
            assert_eq!(version, vec![0x00]);
            assert_eq!(
                payload,
                hex_literal::hex!("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").to_vec()
            );
        }

        #[test]
        fn test_base58check_decode_p2pkh_testnet() {
            let (version, payload) =
                base58check_decode("mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt").unwrap();
            assert_eq!(version, vec![0x6f]);
            assert_eq!(
                payload,
                hex_literal::hex!("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").to_vec()
            );
        }

        #[test]
        fn test_base58check_decode_invalid_checksum() {
            // Modified last character to invalidate checksum
            let result = base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb");
            assert!(result.is_err());
        }

        #[test]
        fn test_base58check_decode_too_short() {
            let result = base58check_decode("1234");
            assert!(result.is_err());
        }

        #[test]
        fn test_base58check_decode_invalid_base58() {
            // Contains invalid base58 characters (0, O, I, l)
            let result = base58check_decode("0OIl");
            assert!(result.is_err());
        }

        #[test]
        fn test_base58check_roundtrip() {
            let test_cases: &[(&[u8], &[u8])] = &[
                (&[0x00], &[0x01, 0x02, 0x03, 0x04, 0x05]),
                (&[0x05], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                (
                    &[0x80],
                    &[
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                        0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    ],
                ),
            ];

            for (version, payload) in test_cases {
                let encoded = base58check_encode(version, payload);
                let (decoded_version, decoded_payload) = base58check_decode(&encoded).unwrap();
                assert_eq!(decoded_version, *version);
                assert_eq!(decoded_payload, *payload);
            }
        }
    }

    mod bech32_tests {
        use super::*;

        #[test]
        fn test_bech32_decode_p2wpkh_mainnet() {
            // SegWit v0 P2WPKH mainnet
            let (hrp, version, data) =
                bech32_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
            assert_eq!(hrp, "bc");
            assert_eq!(version, 0);
            assert_eq!(
                data,
                hex_literal::hex!("751e76e8199196d454941c45d1b3a323f1433bd6").to_vec()
            );
        }

        #[test]
        fn test_bech32_decode_p2wsh_mainnet() {
            // SegWit v0 P2WSH mainnet (32 bytes)
            let (hrp, version, data) =
                bech32_decode("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
                    .unwrap();
            assert_eq!(hrp, "bc");
            assert_eq!(version, 0);
            assert_eq!(
                data,
                hex_literal::hex!(
                    "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
                )
                .to_vec()
            );
        }

        #[test]
        fn test_bech32_decode_p2wpkh_testnet() {
            // SegWit v0 P2WPKH testnet
            let (hrp, version, data) =
                bech32_decode("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
            assert_eq!(hrp, "tb");
            assert_eq!(version, 0);
            assert_eq!(
                data,
                hex_literal::hex!("751e76e8199196d454941c45d1b3a323f1433bd6").to_vec()
            );
        }

        #[test]
        fn test_bech32_decode_p2tr_mainnet() {
            // SegWit v1 P2TR (Taproot) mainnet - uses Bech32m
            let (hrp, version, data) =
                bech32_decode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
                    .unwrap();
            assert_eq!(hrp, "bc");
            assert_eq!(version, 1);
            assert_eq!(
                data,
                hex_literal::hex!(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                )
                .to_vec()
            );
        }

        #[test]
        fn test_bech32_decode_invalid() {
            // Invalid bech32 strings
            assert!(bech32_decode("bc1invalid").is_err());
            assert!(bech32_decode("not_bech32").is_err());
            assert!(bech32_decode("").is_err());
        }

        #[test]
        fn test_bech32_encode_taproot() {
            // Encode Taproot address (uses Bech32m)
            let data = hex_literal::hex!(
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            );
            let encoded = bech32_encode("bc", 1, &data).unwrap();
            // Note: Our encode function uses Bech32m, so it matches Taproot encoding
            assert!(encoded.starts_with("bc1p"));
            assert_eq!(encoded.len(), 62); // bc1p + 58 chars
        }

        #[test]
        fn test_bech32_encode_invalid_hrp() {
            let data = hex_literal::hex!("751e76e8199196d454941c45d1b3a323f1433bd6");
            // Empty HRP is invalid
            assert!(bech32_encode("", 0, &data).is_err());
        }

        #[test]
        fn test_bech32_roundtrip() {
            let test_cases: &[(u8, &[u8])] = &[
                (
                    1,
                    &hex_literal::hex!(
                        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    ),
                ),
                (
                    1,
                    &hex_literal::hex!(
                        "0000000000000000000000000000000000000000000000000000000000000001"
                    ),
                ),
            ];

            for (version, data) in test_cases {
                let encoded = bech32_encode("bc", *version, data).unwrap();
                let (hrp, decoded_version, decoded_data) = bech32_decode(&encoded).unwrap();
                assert_eq!(hrp, "bc");
                assert_eq!(decoded_version, *version);
                assert_eq!(decoded_data, *data);
            }
        }
    }

    mod eip55_tests {
        use super::*;

        #[test]
        fn test_eip55_official_test_vectors() {
            // Official EIP-55 test vectors
            let test_cases: &[(&str, &str)] = &[
                (
                    "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                ),
                (
                    "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                ),
                (
                    "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
                ),
                (
                    "d1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
                ),
            ];

            for (input, expected) in test_cases {
                let addr_bytes: [u8; 20] = hex::decode(input).unwrap().try_into().unwrap();
                let checksummed = eip55_checksum(&addr_bytes);
                assert_eq!(checksummed, *expected, "Failed for input: {}", input);
            }
        }

        #[test]
        fn test_eip55_all_zeros() {
            let addr = [0u8; 20];
            let checksummed = eip55_checksum(&addr);
            assert_eq!(checksummed, "0x0000000000000000000000000000000000000000");
        }

        #[test]
        fn test_eip55_all_ones() {
            let addr = [0xff; 20];
            let checksummed = eip55_checksum(&addr);
            assert_eq!(checksummed, "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF");
        }

        #[test]
        fn test_eip55_length() {
            let addr = hex_literal::hex!("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
            let checksummed = eip55_checksum(&addr);
            // "0x" + 40 hex chars = 42 total
            assert_eq!(checksummed.len(), 42);
            assert!(checksummed.starts_with("0x"));
        }

        #[test]
        fn test_eip55_consistency() {
            // Same address should always produce same checksum
            let addr = hex_literal::hex!("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
            let result1 = eip55_checksum(&addr);
            let result2 = eip55_checksum(&addr);
            assert_eq!(result1, result2);
        }
    }
}
