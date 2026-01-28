//! Utility functions for Ethereum wallet operations.

#[cfg(feature = "alloc")]
use alloc::string::String;

use alloy_primitives::{Address, keccak256};

/// Convert address to checksummed format (EIP-55).
pub fn to_checksum_address(address: &Address) -> String {
    let addr_hex = hex::encode::<&[u8]>(address.as_slice());
    let hash = keccak256(addr_hex.as_bytes());

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in addr_hex.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            let hash_nibble = (hash[i / 2] >> (4 * (1 - i % 2))) & 0xf;
            if hash_nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Convert public key bytes to Ethereum address.
pub fn public_key_to_address(public_key_bytes: &[u8]) -> Address {
    // Skip the first byte (0x04 prefix for uncompressed key) if present
    let key_bytes = if public_key_bytes.len() == 65 && public_key_bytes[0] == 0x04 {
        &public_key_bytes[1..]
    } else {
        public_key_bytes
    };

    let hash = keccak256(key_bytes);
    Address::from_slice(&hash[12..])
}

#[cfg(test)]
mod tests {
    use super::*;

    // EIP-55 official test vectors
    #[test]
    fn test_checksum_address_eip55_vectors() {
        let test_cases = [
            // All caps
            (
                "52908400098527886E0F7030069857D2E4169EE7",
                "0x52908400098527886E0F7030069857D2E4169EE7",
            ),
            (
                "8617E340B3D01FA5F11F306F4090FD50E238070D",
                "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
            ),
            // All lower
            (
                "de709f2102306220921060314715629080e2fb77",
                "0xde709f2102306220921060314715629080e2fb77",
            ),
            (
                "27b1fdb04752bbc536007a920d24acb045561c26",
                "0x27b1fdb04752bbc536007a920d24acb045561c26",
            ),
            // Mixed case (from EIP-55)
            (
                "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
        ];

        for (input, expected) in test_cases {
            let addr = Address::from_slice(&hex::decode(input).unwrap());
            let checksummed = to_checksum_address(&addr);
            assert_eq!(checksummed, expected, "Failed for input: {input}");
        }
    }

    // Test public key to address conversion with known test vector
    // This uses the well-known Ganache test account #0 public key
    #[test]
    fn test_public_key_to_address() {
        // Uncompressed public key (65 bytes with 0x04 prefix)
        let pubkey_hex = "04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39";
        let pubkey = hex::decode(pubkey_hex).unwrap();

        let address = public_key_to_address(&pubkey);
        let checksummed = to_checksum_address(&address);

        // Verified address for this public key
        assert_eq!(checksummed, "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1");
    }

    // Test with 64-byte public key (without 0x04 prefix)
    #[test]
    fn test_public_key_to_address_no_prefix() {
        // Same key without 0x04 prefix (64 bytes)
        let pubkey_hex = "e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39";
        let pubkey = hex::decode(pubkey_hex).unwrap();

        let address = public_key_to_address(&pubkey);
        let checksummed = to_checksum_address(&address);

        // Same address as with prefix
        assert_eq!(checksummed, "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1");
    }

    // Test zero address
    #[test]
    fn test_checksum_zero_address() {
        let addr = Address::ZERO;
        let checksummed = to_checksum_address(&addr);
        assert_eq!(checksummed, "0x0000000000000000000000000000000000000000");
    }
}
