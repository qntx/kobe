//! EIP-191 message hashing utilities.
//!
//! Provides shared functionality for Ethereum personal message signing (EIP-191).

use sha3::{Digest, Keccak256};

/// Compute EIP-191 personal message hash.
///
/// Prefixes the message with "\x19Ethereum Signed Message:\n{length}" and hashes with Keccak256.
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let prefix = b"\x19Ethereum Signed Message:\n";
    let (len_buf, len_used) = format_usize(message.len());

    let mut hasher = Keccak256::new();
    hasher.update(prefix);
    hasher.update(&len_buf[..len_used]);
    hasher.update(message);
    hasher.finalize().into()
}

/// Format usize as decimal string bytes (no_std compatible).
///
/// Returns a tuple of (buffer, bytes_used).
fn format_usize(mut n: usize) -> ([u8; 20], usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();

    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }

    // Left-align the result
    let len = buf.len() - i;
    buf.copy_within(i.., 0);
    (buf, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_usize_zero() {
        let (buf, len) = format_usize(0);
        assert_eq!(&buf[..len], b"0");
    }

    #[test]
    fn test_format_usize_single_digit() {
        let (buf, len) = format_usize(5);
        assert_eq!(&buf[..len], b"5");
    }

    #[test]
    fn test_format_usize_multi_digit() {
        let (buf, len) = format_usize(12345);
        assert_eq!(&buf[..len], b"12345");
    }

    #[test]
    fn test_hash_message() {
        let message = b"Hello, Ethereum!";
        let hash = hash_message(message);
        assert_eq!(hash.len(), 32);
    }
}
