//! Cryptographic hash functions used in cryptocurrency operations.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Compute SHA-256 hash
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute double SHA-256 hash (used in Bitcoin)
#[inline]
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Compute RIPEMD-160 hash
#[inline]
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Hash160 (SHA-256 followed by RIPEMD-160, used in Bitcoin)
#[inline]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// Compute Keccak-256 hash (used in Ethereum)
#[inline]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    mod sha256_tests {
        use super::*;

        #[test]
        fn test_sha256_empty() {
            let hash = sha256(b"");
            assert_eq!(
                hex::encode(hash),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn test_sha256_hello() {
            let hash = sha256(b"hello");
            assert_eq!(
                hex::encode(hash),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            );
        }
    }

    mod double_sha256_tests {
        use super::*;

        #[test]
        fn test_double_sha256_empty() {
            let hash = double_sha256(b"");
            assert_eq!(
                hex::encode(hash),
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
            );
        }

        #[test]
        fn test_double_sha256_hello() {
            let hash = double_sha256(b"hello");
            let expected = sha256(&sha256(b"hello"));
            assert_eq!(hash, expected);
        }
    }

    mod ripemd160_tests {
        use super::*;

        #[test]
        fn test_ripemd160_empty() {
            let hash = ripemd160(b"");
            assert_eq!(
                hex::encode(hash),
                "9c1185a5c5e9fc54612808977ee8f548b2258d31"
            );
        }

        #[test]
        fn test_ripemd160_hello() {
            let hash = ripemd160(b"hello");
            assert_eq!(
                hex::encode(hash),
                "108f07b8382412612c048d07d13f814118445acd"
            );
        }
    }

    mod hash160_tests {
        use super::*;

        #[test]
        fn test_hash160_hello() {
            let hash = hash160(b"hello");
            assert_eq!(
                hex::encode(hash),
                "b6a9c8c230722b7c748331a8b450f05566dc7d0f"
            );
        }

        #[test]
        fn test_hash160_empty() {
            let hash = hash160(b"");
            assert_eq!(
                hex::encode(hash),
                "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
            );
        }
    }

    mod keccak256_tests {
        use super::*;

        #[test]
        fn test_keccak256_hello() {
            let hash = keccak256(b"hello");
            assert_eq!(
                hex::encode(hash),
                "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
            );
        }

        #[test]
        fn test_keccak256_empty() {
            let hash = keccak256(b"");
            assert_eq!(
                hex::encode(hash),
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
            );
        }
    }
}
