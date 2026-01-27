//! Utility functions for Ethereum wallet operations.

use alloy_primitives::{Address, keccak256};

/// Convert address to checksummed format (EIP-55).
pub fn to_checksum_address(address: &Address) -> String {
    let addr_hex = hex::encode(address.as_slice());
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

    #[test]
    fn test_checksum_address() {
        let addr =
            Address::from_slice(&hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap());
        let checksummed = to_checksum_address(&addr);
        assert_eq!(checksummed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }
}
